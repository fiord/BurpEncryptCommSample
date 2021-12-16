package burp;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import com.google.common.primitives.Bytes;
import net.razorvine.pyro.*;

public class BurpExtender implements IBurpExtender, IHttpListener {
    private PrintWriter stdout;
    private PrintWriter stderr;

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("Brida Encrypt Communication Sample Plugin");

        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.registerHttpListener(this);
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (toolFlag == IBurpExtenderCallbacks.TOOL_SCANNER ||
                toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER ||
                toolFlag == IBurpExtenderCallbacks.TOOL_INTRUDER) {
            // request
            if (messageIsRequest) {
                byte[] request = messageInfo.getRequest();
                IParameter contentParameter = helpers.getRequestParameter(request, "name");
                if (contentParameter != null) {
                    String ret = "";
                    String pyroUrl = "PYRO:BridaServicePyro@localhost:9999";
                    try {
                        PyroProxy pp = new PyroProxy(new PyroURI(pyroUrl));
                        ret = (String) pp.call("callexportfunction",
                                "dev.fiord.encrypted_communication_sample.data.LoginDataSource.encrypt",
                                new String[] { contentParameter.getValue() });
                        pp.close();
                    } catch (IOException e) {
                        // EXCEPTION HANDLING
                        stderr.println(e);
                        StackTraceElement[] exceptionElements = e.getStackTrace();
                        for (int i = 0; i < exceptionElements.length; i++) {
                            stderr.println(exceptionElements[i].toString());
                        }
                    }

                    IParameter newTestParameter = helpers.buildParameter(contentParameter.getName(),
                            helpers.urlEncode(ret), contentParameter.getType());
                    byte[] newRequest = helpers.updateParameter(request, newTestParameter);
                    messageInfo.setRequest(newRequest);
                }
            }
            // response
            else {
                byte[] request = messageInfo.getRequest();
                IRequestInfo requestInfo = helpers.analyzeRequest(request);
                String body = new String(Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length),
                        java.nio.charset.StandardCharsets.UTF_8);
                if (body != null) {
                    String ret = "";
                    String pyroUrl = "PYRO:BridaServicePyro@localhost:9999";
                    try {
                        PyroProxy pp = new PyroProxy(new PyroURI(pyroUrl));
                        ret = (String) pp.call("callexportfunction",
                                "dev.fiord.encrypted_communication_sample.data.LoginDataSource.decrypt",
                                new String[] { body });
                        pp.close();
                    } catch (IOException e) {
                        // EXCEPTION HANDLING
                        stderr.println(e);
                        StackTraceElement[] exceptionElements = e.getStackTrace();
                        for (int i = 0; i < exceptionElements.length; i++) {
                            stderr.println(exceptionElements[i].toString());
                        }
                    }

                    byte[] newRequest = Bytes.concat(
                            Arrays.copyOfRange(request, 0, requestInfo.getBodyOffset()),
                            ret.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    messageInfo.setRequest(newRequest);
                }
            }
        }
    }
}