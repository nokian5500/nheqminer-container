package ua.pb.ceb.ipay2.servlets.core;

import com.amazonaws.util.json.JSONException;
import com.amazonaws.util.json.JSONObject;
import ua.pb.ceb.ipay2.utils.Conveyor;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Created by sgoroshko on 21.09.15.
 */
abstract class AbstractBoneServlet extends AbstractServlet {
    @Override
    protected void service(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            process(request, response);
        } catch (Throwable throwable) {
            throwable.printStackTrace();
            try {
                JSONObject jsonResponse = new JSONObject();
//                jsonResponse.put("ercode", QSException.Code.CODE1000);
                jsonResponse.put("ermess", "Ошибка сервера");

                writeResponse(response, jsonResponse);

                request.getAsyncContext().complete();
            } catch (JSONException impossible) {
                impossible.printStackTrace();
            }
        }
    }

    private void process(HttpServletRequest request, HttpServletResponse response) throws JSONException, IOException {
        JSONObject jsonRequest = new JSONObject();
        final String method = request.getMethod();
        switch (method) {
            case "GET":
                getToJSON(request, jsonRequest);
                break;

            case "POST":
                postToJSON(request, jsonRequest);
                break;

            default: throw new IOException("reason: unsupported method");
        }
        final String reference = Conveyor.getNewRef();
        log(reference, this.getClass().getName(), method, jsonRequest.toString());
        handle(jsonRequest, response, reference);
    }

    protected abstract void handle(JSONObject jsonRequest, HttpServletResponse response, String reference) throws JSONException;

}
