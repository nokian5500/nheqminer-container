package ua.pb.ceb.ipay2.utils;

import com.amazonaws.services.simpleworkflow.model.Run;
import com.amazonaws.util.json.JSONArray;
import com.amazonaws.util.json.JSONException;
import com.amazonaws.util.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

public class Conveyor {
    private static final String cpURL = "https://cp.privatbank.ua/api/1/json/";

    public final String url;
    public final JSONObject data;

    private Conveyor (String url, JSONObject data) {
        this.url = url;
        this.data = data;
    }

    public static String getNewRef() {
        String ref = String.valueOf(new Random().nextInt(1000000));
        ref += System.nanoTime();
        // todo добавить переменную для идентификации инстанса
        return "IPAY2_" + ref;
    }

    public static class Operation {
        private Object object;
        private Type type;
        private JSONObject data;
        private JSONObject extra;
        private Map <Param, String> param = new HashMap <> ();

        public enum Type {
            create,
            modify
        }

        public enum Object {
            task,
            conv
        }

        public enum Param {
            obj_id,
            conv_id,
            ref
        }

        public Operation (Object object, Type type) {
            this.object = object;
            this.type = type;
        }

        public Operation addData (String key, java.lang.Object value) throws JSONException {
            if (data == null) {
                data = new JSONObject ();
            }
            data.put (key, value);
            return this;
        }

        public Operation addData (org.jsonnew.JSONObject value) throws JSONException {
            if (data == null) {
                data = new JSONObject (value.toString());
            } else {
                // дописать адекватную функцию
                // которая будет добавлять json до уже существующего
                throw new RuntimeException("");
            }
            return this;
        }

        public Operation addExtra (String key, java.lang.Object value) throws JSONException {
            if (extra == null) {
                extra = new JSONObject ();
            }
            extra.put (key, value);
            return this;
        }

        public Operation addParam (Param param, String value) {
            this.param.put (param, value);
            return this;
        }

    }

    public static class Builder {
        private String apiLogin;
        private String apiSecret;
        private List <Operation> operations = new ArrayList <Operation> ();

        public Builder (String apiLogin, String apiSecret) {
            this.apiLogin = apiLogin;
            this.apiSecret = apiSecret;
        }

        public Builder addOperation (Operation operation) {
            operations.add (operation);
            return this;
        }

        public Conveyor build () throws JSONException {
            final String unixTime = String.valueOf (System.currentTimeMillis () / 1000);
            final JSONObject jsonObject = new JSONObject();
            final JSONArray jsonArray = new JSONArray();
            for (Operation operation : operations) {
                JSONObject operations = new JSONObject();
                operations.put ("obj", operation.object.name ());
                operations.put ("type", operation.type.name ());
                if (operation.data != null) {
                    operations.put ("data", operation.data);
                }
                if (operation.extra != null) {
                    operations.put ("extra", operation.extra);
                }
                for (Map.Entry <Operation.Param, String> entry : operation.param.entrySet ()) {
                    operations.put (entry.getKey ().name (), entry.getValue ());
                }
                jsonArray.put (operations);
            }
            jsonObject.put ("ops", jsonArray);
            String signature = Utils.bytesToHex (Utils.SHA1 (unixTime + apiSecret + jsonObject.toString () + apiSecret, "UTF-8"));
            return new Conveyor (cpURL + apiLogin + '/' + unixTime + '/' + signature, jsonObject);
        }

    }

}
