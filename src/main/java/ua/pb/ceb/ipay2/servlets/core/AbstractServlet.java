package ua.pb.ceb.ipay2.servlets.core;

import com.amazonaws.util.json.JSONException;
import com.amazonaws.util.json.JSONObject;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Enumeration;
import java.util.Set;

/**
 * Created by sgoroshko on 21.09.15.
 */
abstract class AbstractServlet extends HttpServlet {
    private static final boolean LogOn = true;
    private static boolean isLogOn() {
        return LogOn;
    }

    protected void postToJSON(HttpServletRequest request, JSONObject jsonRequest) throws JSONException {
        final Set<String> keys = request.getParameterMap().keySet();
        System.err.printf(keys.size() + "\n");
        for (String key: keys) {
            System.err.printf(key + " " + request.getParameter(key) + "\n");
            jsonRequest.put(key, request.getParameter(key));
        }
    }

    protected void getToJSON(HttpServletRequest request, JSONObject jsonRequest) throws JSONException {
        final Enumeration<String> keys = request.getParameterNames();
        while (keys.hasMoreElements()) {
            final String key = keys.nextElement();
            jsonRequest.put(key, request.getParameter(key));
        }
    }

    protected void log(String reference, String servletName, String method, String params) {
        if (isLogOn()) {
            System.err.println("[" + reference + "] " + servletName + " " + method
                    + "\n[" + reference + "] " + params);
        }
    }

    protected void writeResponse(HttpServletResponse response, JSONObject jsonResponse) throws IOException {
        response.setContentType("application/json;charset=UTF-8");
        PrintWriter writer = response.getWriter();
        writer.print(jsonResponse.toString());
        writer.flush();
        writer.close();
    }
}
