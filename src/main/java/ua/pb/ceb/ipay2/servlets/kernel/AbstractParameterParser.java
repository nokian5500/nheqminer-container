package ua.pb.ceb.ipay2.servlets.kernel;

import org.jsonnew.JSONObject;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;

/**
 * Created by sgoroshko on 21.09.15.
 */
public abstract class AbstractParameterParser extends AbstractExceptionHandler {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        JSONObject jsonRequest = new JSONObject();
        final Set<String> keys = request.getParameterMap().keySet();
        for (String key: keys) {
//            jsonRequest.put(key, request.getParameter(key));
        }
    }
}
