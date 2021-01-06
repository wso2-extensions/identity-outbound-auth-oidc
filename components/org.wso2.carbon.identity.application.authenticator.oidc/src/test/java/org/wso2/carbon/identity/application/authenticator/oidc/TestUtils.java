package org.wso2.carbon.identity.application.authenticator.oidc;

import org.apache.commons.lang.StringUtils;

import java.nio.file.Paths;

public class TestUtils {

    public static String getFilePath(String fileName) {

        if (StringUtils.isNotBlank(fileName)) {
            return Paths.get(System.getProperty("user.dir"), "src", "test", "resources", "conf", fileName).toString();
        }
        return null;
    }

}
