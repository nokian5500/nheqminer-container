package ua.pb.ceb.ipay2.servlets.kernel;

import org.jsonnew.JSONObject;
import ua.pb.ceb.ipay2.utils.Conveyor;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletResponse;

/**
 * Created by sgoroshko on 21.09.15.
 */
abstract class AbstractExceptionHandler extends HttpServlet {
    private static final boolean logOn = true;
    public boolean isLogOn() {
        return logOn;
    }

    private void log(String method, String request, String reference) {
        if (isLogOn()) {
            System.err.println("[" + reference + "]\t" + this.getClass().getName() + "\t" + method
                    + "\n[" + reference + "]\t" + request);
        }
    }

    protected void handle(JSONObject jsonRequest, HttpServletResponse response, String method) throws Exception {
        try {
            final String reference = Conveyor.getNewRef();
            log(method, jsonRequest.toString(), reference);
            handle(jsonRequest, response);
        } catch (Throwable throwable) {
            throwable.printStackTrace();
        }
    }

    protected abstract void handle(JSONObject jsonRequest, HttpServletResponse response);
}
