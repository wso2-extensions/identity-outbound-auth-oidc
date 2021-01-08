package org.wso2.carbon.identity.application.authenticator.oidc;

import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;

/**
 * This class handle logout related errors
 */
public class LogoutException extends FrameworkException {

    public LogoutException(String message) {

        super(message);
    }

    public LogoutException(String errorCode, String message) {

        super(errorCode, message);
    }

    public LogoutException(String message, Throwable cause) {

        super(message, cause);
    }

    public LogoutException(String errorCode, String message, Throwable cause) {

        super(errorCode, message, cause);
    }
}
