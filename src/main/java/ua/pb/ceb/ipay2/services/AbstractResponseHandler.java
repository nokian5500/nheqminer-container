package ua.pb.ceb.ipay2.services;

import javax.servlet.ServletContext;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by sgoroshko on 21.09.15.
 */
abstract class AbstractResponseHandler {
    protected Map<String, ServletContext> servletContextMap = new ConcurrentHashMap<>();

}
