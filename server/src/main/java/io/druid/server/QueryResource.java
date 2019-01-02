/*
 * Licensed to Metamarkets Group Inc. (Metamarkets) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. Metamarkets licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package io.druid.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.joda.ser.DateTimeSerializer;
import com.fasterxml.jackson.jaxrs.smile.SmileMediaTypes;
import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Iterables;
import com.google.common.collect.Sets;
import com.google.common.io.CountingOutputStream;
import com.google.inject.Inject;
import io.druid.java.util.emitter.EmittingLogger;
import io.druid.client.DirectDruidClient;
import io.druid.guice.LazySingleton;
import io.druid.guice.annotations.Json;
import io.druid.guice.annotations.Smile;
import io.druid.java.util.common.StringUtils;
import io.druid.java.util.common.guava.Sequence;
import io.druid.java.util.common.guava.Yielder;
import io.druid.java.util.common.guava.Yielders;
import io.druid.query.GenericQueryMetricsFactory;
import io.druid.query.Query;
import io.druid.query.QueryContexts;
import io.druid.query.QueryInterruptedException;
import io.druid.server.metrics.QueryCountStatsProvider;
import io.druid.server.security.Access;
import io.druid.server.security.AuthConfig;
import io.druid.server.security.AuthorizerMapper;
import io.druid.server.security.AuthorizationUtils;
import io.druid.server.security.ForbiddenException;
import org.joda.time.DateTime;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.StreamingOutput;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 查询入口
 */
@LazySingleton
@Path("/druid/v2/")
public class QueryResource implements QueryCountStatsProvider
{
  //实例化日志监控对象
  protected static final EmittingLogger log = new EmittingLogger(QueryResource.class);
  @Deprecated // use SmileMediaTypes.APPLICATION_JACKSON_SMILE
  protected static final String APPLICATION_SMILE = "application/smile";

  protected static final int RESPONSE_CTX_HEADER_LEN_LIMIT = 7 * 1024;

  public static final String HEADER_IF_NONE_MATCH = "If-None-Match";
  //ETag就是服务器生成的一个标记，用来标识返回值是否有变化。第一次发起http请求时，服务器会返回一个ETag。
  //第二次发送同一个请求时，客户端会同时发送一个If-None-Match，而它就是Etag的值。然后服务端会对比这个客户端发送过来的Etag是否与服务器相同，如果相同就将If-None-Match
  //的值设置为false，返回状态304，客户端继续使用本地缓存。不解析服务器返回的数据（这种场景服务器也不返回数据，因为服务器数据没有变化）
  //如果不相同，就将If-None-Match的值设为true，返回状态为200，客户端重新解析服务器返回的数据
  public static final String HEADER_ETAG = "ETag";

  protected final QueryLifecycleFactory queryLifecycleFactory;
  //ObjectMapper 是 Jackson中的实现类
  protected final ObjectMapper jsonMapper;
  protected final ObjectMapper smileMapper;
  protected final ObjectMapper serializeDateTimeAsLongJsonMapper;
  protected final ObjectMapper serializeDateTimeAsLongSmileMapper;
  //管理query的操作，如取消、注册
  protected final QueryManager queryManager;
  //查询权限认证
  protected final AuthConfig authConfig;
  //权限相关
  protected final AuthorizerMapper authorizerMapper;
  //创建queryMetric实例的工厂
  private final GenericQueryMetricsFactory queryMetricsFactory;

  //AtomicLong 是jdk中的类型是线程安全的。
  private final AtomicLong successfulQueryCount = new AtomicLong();
  private final AtomicLong failedQueryCount = new AtomicLong();
  private final AtomicLong interruptedQueryCount = new AtomicLong();

  @Inject //@inject  注入
  public QueryResource(
          QueryLifecycleFactory queryLifecycleFactory,
          @Json ObjectMapper jsonMapper,
          @Smile ObjectMapper smileMapper,
          QueryManager queryManager,
          AuthConfig authConfig,
          AuthorizerMapper authorizerMapper,
          GenericQueryMetricsFactory queryMetricsFactory
  )
  {
    this.queryLifecycleFactory = queryLifecycleFactory;
    this.jsonMapper = jsonMapper;
    this.smileMapper = smileMapper;
    this.serializeDateTimeAsLongJsonMapper = serializeDataTimeAsLong(jsonMapper);
    this.serializeDateTimeAsLongSmileMapper = serializeDataTimeAsLong(smileMapper);
    this.queryManager = queryManager;
    this.authConfig = authConfig;
    this.authorizerMapper = authorizerMapper;
    this.queryMetricsFactory = queryMetricsFactory;
  }

  //根据queryID，取消查询。
  @DELETE
  @Path("{id}")
  @Produces(MediaType.APPLICATION_JSON)
  public Response cancelQuery(@PathParam("id") String queryId, @Context final HttpServletRequest req)
  {
    if (log.isDebugEnabled()) {
      log.debug("Received cancel request for query [%s]", queryId);
    }
    //getQueryDatasources()方法获取数据源
    Set<String> datasources = queryManager.getQueryDatasources(queryId);
    if (datasources == null) {
      log.warn("QueryId [%s] not registered with QueryManager, cannot cancel", queryId);
      datasources = Sets.newTreeSet();
    }

    //是否通过权限认证
    Access authResult = AuthorizationUtils.authorizeAllResourceActions(
            req,
            Iterables.transform(datasources, AuthorizationUtils.DATASOURCE_WRITE_RA_GENERATOR),
            authorizerMapper
    );

    if (!authResult.isAllowed()) {
      throw new ForbiddenException(authResult.toString());
    }

    //调用queryManager的cancelQuery()方法取消查询id，返回状态。
    queryManager.cancelQuery(queryId);
    return Response.status(Response.Status.ACCEPTED).build();
  }

  //@consumes是指定处理请求的提交内容类型
  //注解@Produces用于定义方法的响应实体的数据类型，可以定义一个或多个
  @POST
  @Produces({MediaType.APPLICATION_JSON, SmileMediaTypes.APPLICATION_JACKSON_SMILE})
  @Consumes({MediaType.APPLICATION_JSON, SmileMediaTypes.APPLICATION_JACKSON_SMILE, APPLICATION_SMILE})
  public Response doPost(
          final InputStream in,
          @QueryParam("pretty") final String pretty,
          @Context final HttpServletRequest req // used to get request content-type, remote address and auth-related headers
  ) throws IOException
  {
    //InputStream in 输入的是查询的语句
    //管理query的生名周期。factorize方法返回QueryLifecycle实例化对象
    final QueryLifecycle queryLifecycle = queryLifecycleFactory.factorize();

    Query<?> query = null;

    //实例化返回的消息体类型
    final ResponseContext context = createContext(req.getContentType(), pretty != null);

    //获取当前线程运行的名字
    final String currThreadName = Thread.currentThread().getName();
    try {
      //第一步：生命周期的初始化，readQuery方法可以获取query的类型
      queryLifecycle.initialize(readQuery(req, in, context));
      //返回query对象,得知query的类型是timeseriesquery还是别的类型的query
      query = queryLifecycle.getQuery();
      //返回queryID
      final String queryId = query.getId();

      //Thread是jadk的线程实现类，设置当前运行线程的名字
      Thread.currentThread()
              .setName(StringUtils.format("%s[%s_%s_%s]", currThreadName, query.getType(), query.getDataSource().getNames(), queryId));
      if (log.isDebugEnabled()) {
        log.debug("Got query [%s]", query);
      }
      //第二步：认证授权
      final Access authResult = queryLifecycle.authorize(req);
      if (!authResult.isAllowed()) {
        throw new ForbiddenException(authResult.toString());
      }
      //第三步：执行查询操作
      //调用execute方法，返回查询QueryResponse对象。queryResponse对象中包含查询出来的结果
      final QueryLifecycle.QueryResponse queryResponse = queryLifecycle.execute();
      //获得查询结果，结果是是sequence
      final Sequence<?> results = queryResponse.getResults();
      //返回响应内容
      final Map<String, Object> responseContext = queryResponse.getResponseContext();

      //获取Etag的值，HEADER_IF_NONE_MATCH其实就是Etag的值
      final String prevEtag = getPreviousEtag(req);

      //如果Etag有值，并且和原来的值相等，就直接返回Response，如果不相等就发起新的请求。
      if (prevEtag != null && prevEtag.equals(responseContext.get(HEADER_ETAG))) {
        return Response.notModified().build();
      }
      //Yielder对象可以看作一个链表，调用yielder的get方法可以获取当前头元素的值，调用next方法获取下一个yielder对象。
      //将Sequence转换成Yielder，这个Yielder每执行一次就返回一个元素，类似于迭代器，方便序列化
      final Yielder<?> yielder = Yielders.each(results);

      try {
        boolean shouldFinalize = QueryContexts.isFinalize(query, true);

        //是否序列化DataTime类型为Long类型
        boolean serializeDateTimeAsLong =
                QueryContexts.isSerializeDateTimeAsLong(query, false)
                        || (!shouldFinalize && QueryContexts.isSerializeDateTimeAsLongInner(query, false));

        //将responseContext写出，利用jsonWrite将Yielder序列化写入到Response中。
        final ObjectWriter jsonWriter = context.newOutputWriter(serializeDateTimeAsLong);
        Response.ResponseBuilder builder = Response
                .ok(
                        new StreamingOutput()
                        {
                          @Override
                          public void write(OutputStream outputStream) throws IOException, WebApplicationException
                          {
                            Exception e = null;

                            CountingOutputStream os = new CountingOutputStream(outputStream);
                            try {
                              // json serializer will always close the yielder
                              jsonWriter.writeValue(os, yielder);

                              os.flush(); // Some types of OutputStream suppress flush errors in the .close() method.
                              os.close();
                            }
                            catch (Exception ex) {
                              e = ex;
                              log.error(ex, "Unable to send query response.");
                              throw Throwables.propagate(ex);
                            }
                            finally {
                              Thread.currentThread().setName(currThreadName);

                              queryLifecycle.emitLogsAndMetrics(e, req.getRemoteAddr(), os.getCount());

                              if (e == null) {
                                successfulQueryCount.incrementAndGet();
                              } else {
                                failedQueryCount.incrementAndGet();
                              }
                            }
                          }
                        },
                        context.getContentType()
                )
                .header("X-Druid-Query-Id", queryId);

        if (responseContext.get(HEADER_ETAG) != null) {
          builder.header(HEADER_ETAG, responseContext.get(HEADER_ETAG));
          responseContext.remove(HEADER_ETAG);
        }

        DirectDruidClient.removeMagicResponseContextFields(responseContext);

        //Limit the response-context header, see https://github.com/druid-io/druid/issues/2331
        //Note that Response.ResponseBuilder.header(String key,Object value).build() calls value.toString()
        //and encodes the string using ASCII, so 1 char is = 1 byte
        String responseCtxString = jsonMapper.writeValueAsString(responseContext);
        if (responseCtxString.length() > RESPONSE_CTX_HEADER_LEN_LIMIT) {
          log.warn("Response Context truncated for id [%s] . Full context is [%s].", queryId, responseCtxString);
          responseCtxString = responseCtxString.substring(0, RESPONSE_CTX_HEADER_LEN_LIMIT);
        }

        return builder
                .header("X-Druid-Response-Context", responseCtxString)
                .build();
      }
      catch (Exception e) {
        // make sure to close yielder if anything happened before starting to serialize the response.
        yielder.close();
        throw Throwables.propagate(e);
      }
      finally {
        // do not close yielder here, since we do not want to close the yielder prior to
        // StreamingOutput having iterated over all the results
      }
    }
    catch (QueryInterruptedException e) {
      interruptedQueryCount.incrementAndGet();
      queryLifecycle.emitLogsAndMetrics(e, req.getRemoteAddr(), -1);
      return context.gotError(e);
    }
    catch (ForbiddenException e) {
      // don't do anything for an authorization failure, ForbiddenExceptionMapper will catch this later and
      // send an error response if this is thrown.
      throw e;
    }
    catch (Exception e) {
      failedQueryCount.incrementAndGet();
      queryLifecycle.emitLogsAndMetrics(e, req.getRemoteAddr(), -1);

      log.makeAlert(e, "Exception handling request")
              .addData("exception", e.toString())
              .addData("query", query != null ? query.toString() : "unparseable query")
              .addData("peer", req.getRemoteAddr())
              .emit();

      return context.gotError(e);
    }
    finally {
      Thread.currentThread().setName(currThreadName);
    }
  }

  private static Query<?> readQuery(
          final HttpServletRequest req,
          final InputStream in,
          final ResponseContext context
  ) throws IOException
  {
    //获取query类型，根据传入的query语句映射成不同的query对象
    Query baseQuery = context.getObjectMapper().readValue(in, Query.class);
    String prevEtag = getPreviousEtag(req);
    if (prevEtag != null) {
      baseQuery = baseQuery.withOverriddenContext(
              ImmutableMap.of(HEADER_IF_NONE_MATCH, prevEtag)
      );
    }

    return baseQuery;
  }

  private static String getPreviousEtag(final HttpServletRequest req)
  {
    return req.getHeader(HEADER_IF_NONE_MATCH);
  }

  /**
   * 把DataTime类型转为Long类型
   * @param mapper
   * @return
   */
  protected ObjectMapper serializeDataTimeAsLong(ObjectMapper mapper)
  {
    //调用Jackson的方法
    return mapper.copy().registerModule(new SimpleModule().addSerializer(DateTime.class, new DateTimeSerializer()));
  }

  /**
   * 新建返回的消息体
   * @param requestType  返回类型
   * @param pretty
   * @return
   */
  protected ResponseContext createContext(String requestType, boolean pretty)
  {
    boolean isSmile = SmileMediaTypes.APPLICATION_JACKSON_SMILE.equals(requestType) ||
            APPLICATION_SMILE.equals(requestType);
    String contentType = isSmile ? SmileMediaTypes.APPLICATION_JACKSON_SMILE : MediaType.APPLICATION_JSON;
    return new ResponseContext(
            contentType,
            isSmile ? smileMapper : jsonMapper,
            isSmile ? serializeDateTimeAsLongSmileMapper : serializeDateTimeAsLongJsonMapper,
            pretty
    );
  }

  /**
   * ResponseContext 定义了返回内容的类型。
   */
  protected static class ResponseContext
  {

    private final String contentType;
    private final ObjectMapper inputMapper;
    private final ObjectMapper serializeDateTimeAsLongInputMapper;
    private final boolean isPretty;

    ResponseContext(
            String contentType,
            ObjectMapper inputMapper,
            ObjectMapper serializeDateTimeAsLongInputMapper,
            boolean isPretty
    )
    {
      this.contentType = contentType;
      this.inputMapper = inputMapper;
      this.serializeDateTimeAsLongInputMapper = serializeDateTimeAsLongInputMapper;
      this.isPretty = isPretty;
    }

    String getContentType()
    {
      return contentType;
    }

    public ObjectMapper getObjectMapper()
    {
      return inputMapper;
    }

    ObjectWriter newOutputWriter(boolean serializeDateTimeAsLong)
    {
      ObjectMapper mapper = serializeDateTimeAsLong ? serializeDateTimeAsLongInputMapper : inputMapper;
      return isPretty ? mapper.writerWithDefaultPrettyPrinter() : mapper.writer();
    }

    Response ok(Object object) throws IOException
    {
      return Response.ok(newOutputWriter(false).writeValueAsString(object), contentType).build();
    }

    Response gotError(Exception e) throws IOException
    {
      return Response.serverError()
              .type(contentType)
              .entity(newOutputWriter(false).writeValueAsBytes(QueryInterruptedException.wrapIfNeeded(e)))
              .build();
    }
  }


  /**
   * 返回查询成功的次数
   * @return
   */
  @Override
  public long getSuccessfulQueryCount()
  {
    return successfulQueryCount.get();
  }

  /**
   * 返回查询失败的次数
   * @return
   */
  @Override
  public long getFailedQueryCount()
  {
    return failedQueryCount.get();
  }

  /**
   * 返回查询中断的次数
   * @return
   */
  @Override
  public long getInterruptedQueryCount()
  {
    return interruptedQueryCount.get();
  }
}
