package se.sopa.trustmenot;

import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;

import static de.robv.android.xposed.XposedHelpers.*;

public class Main implements IXposedHookZygoteInit {

    private static final String SSL_CLASS_NAME = "com.android.org.conscrypt.TrustManagerImpl";
    private static final String CONSCRYPT_SOCKET_CLASS_NAME = "com.android.org.conscrypt.ConscryptFileDescriptorSocket";
    private static final String OKHTTP_CLASS_NAME = "okhttp3.CertificatePinner";
    private static final String APPMATTUS_CT_CLASS_NAME = "com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor";
    private static final String SSL_METHOD_NAME = "checkTrustedRecursive";
    private static final String SOCKET_METHOD_NAME = "verifyCertificateChain";
    private static final String OKHTTP_METHOD_NAME = "check";
    private static final String APPMATTUS_CT_METHOD_NAME = "verifyCertificateChain";
    private static final String RAW_CUSTOM_PINNED_METHOD_NAME = "checkCustomPinned";
    private static final Class<?> SSL_RETURN_TYPE = List.class;
    private static final Class<?> SSL_RETURN_PARAM_TYPE = X509Certificate.class;

    @Override
    public void initZygote(StartupParam startupParam) throws Throwable {
        XposedBridge.log("Suppe loading...");
        int hookedMethods = 0;

        hookedMethods += hookMethods(SSL_CLASS_NAME, SSL_METHOD_NAME, this::checkSSLMethod);
        hookedMethods += hookMethods(CONSCRYPT_SOCKET_CLASS_NAME, SOCKET_METHOD_NAME, method -> method.getName().equals(SOCKET_METHOD_NAME));
        hookedMethods += hookMethods(OKHTTP_CLASS_NAME, OKHTTP_METHOD_NAME, method -> method.getName().equals(OKHTTP_METHOD_NAME));
        hookedMethods += hookMethods(APPMATTUS_CT_CLASS_NAME, APPMATTUS_CT_METHOD_NAME, method -> method.getName().equals(APPMATTUS_CT_METHOD_NAME));
        hookedMethods += hookMethods(RAW_CUSTOM_PINNED_METHOD_NAME, RAW_CUSTOM_PINNED_METHOD_NAME, method -> method.getName().equals(RAW_CUSTOM_PINNED_METHOD_NAME));

        XposedBridge.log(String.format(Locale.ENGLISH, "Suppe loaded! Hooked %d methods", hookedMethods));
    }

    private int hookMethods(String className, String methodName, MethodChecker checker) {
        int count = 0;
        try {
            for (Method method : findClass(className, null).getDeclaredMethods()) {
                if (!checker.check(method)) {
                    continue;
                }

                List<Object> params = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
                params.add(new XC_MethodReplacement() {
                    @Override
                    protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                        return methodName.equals(SSL_METHOD_NAME) ? new ArrayList<X509Certificate>() : null;
                    }
                });

                XposedBridge.log("Hooking method:");
                XposedBridge.log(method.toString());
                findAndHookMethod(className, null, methodName, params.toArray());
                count++;
            }
        } catch (Throwable t) {
            XposedBridge.log("Failed to hook methods for class: " + className);
            XposedBridge.log(t);
        }
        return count;
    }

    private boolean checkSSLMethod(Method method) {
        if (!method.getName().equals(SSL_METHOD_NAME)) {
            return false;
        }

        if (!SSL_RETURN_TYPE.isAssignableFrom(method.getReturnType())) {
            return false;
        }

        Type returnType = method.getGenericReturnType();
        if (!(returnType instanceof ParameterizedType)) {
            return false;
        }

        Type[] args = ((ParameterizedType) returnType).getActualTypeArguments();
        return args.length == 1 && args[0].equals(SSL_RETURN_PARAM_TYPE);
    }

    private interface MethodChecker {
        boolean check(Method method);
    }
}
