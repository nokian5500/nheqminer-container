package ua.pb.ceb.ipay2.servlets.core;

import com.amazonaws.util.json.JSONException;
import com.amazonaws.util.json.JSONObject;
import ua.pb.ceb.ipay2.utils.Conveyor;

import javax.servlet.http.HttpServletResponse;

/**
 * Created by sgoroshko on 21.09.15.
 */
public abstract class RequestHandler extends AbstractBoneServlet {
    @Override
    protected void handle(JSONObject jsonRequest, HttpServletResponse response, String reference) throws JSONException {
        Conveyor conveyor = new Conveyor.Builder("apiLogin", "apiSecret")
                .addOperation(new Conveyor.Operation(Conveyor.Operation.Object.task, Conveyor.Operation.Type.create)
                .addParam(Conveyor.Operation.Param.conv_id, "")
                .addParam(Conveyor.Operation.Param.ref, reference)
                .addData("data", jsonRequest)).build();

    }
}
