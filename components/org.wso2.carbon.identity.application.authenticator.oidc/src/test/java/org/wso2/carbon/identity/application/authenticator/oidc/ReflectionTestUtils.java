/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.oidc;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public final class ReflectionTestUtils {

    private ReflectionTestUtils() {
    }

    public static Object invokePrivateMethod(Object target, String methodName, Class<?>[] parameterTypes,
                                             Object... args) throws Exception {
        Method method = target.getClass().getDeclaredMethod(methodName, parameterTypes);
        method.setAccessible(true);
        try {
            return method.invoke(target, args);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            throw e;
        }
    }

    /**
     * Invokes a private method without requiring explicit parameter types.
     * This method infers parameter types from the provided arguments.
     *
     * @param target     the object instance to invoke the method on
     * @param methodName the name of the method to invoke
     * @param args       the arguments to pass to the method
     * @return the result of the method invocation
     * @throws Exception if the method cannot be invoked
     */
    public static Object invokePrivateMethod(Object target, String methodName, Object... args) throws Exception {
        Class<?>[] parameterTypes = new Class<?>[args.length];
        for (int i = 0; i < args.length; i++) {
            parameterTypes[i] = args[i] != null ? args[i].getClass() : null;
        }

        Method method = findMethod(target.getClass(), methodName, args);
        if (method == null) {
            throw new NoSuchMethodException("Method " + methodName + " not found in " + target.getClass());
        }

        method.setAccessible(true);
        try {
            return method.invoke(target, args);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            throw e;
        }
    }

    private static Method findMethod(Class<?> clazz, String methodName, Object... args) {
        Method[] methods = clazz.getDeclaredMethods();
        for (Method method : methods) {
            if (method.getName().equals(methodName) && method.getParameterCount() == args.length) {
                Class<?>[] paramTypes = method.getParameterTypes();
                boolean match = true;
                for (int i = 0; i < args.length; i++) {
                    if (args[i] != null && !paramTypes[i].isAssignableFrom(args[i].getClass())) {
                        // Check for primitive type compatibility
                        if (!isPrimitiveMatch(paramTypes[i], args[i].getClass())) {
                            match = false;
                            break;
                        }
                    }
                }
                if (match) {
                    return method;
                }
            }
        }
        return null;
    }

    private static boolean isPrimitiveMatch(Class<?> primitiveType, Class<?> wrapperType) {
        if (primitiveType == boolean.class && wrapperType == Boolean.class) return true;
        if (primitiveType == byte.class && wrapperType == Byte.class) return true;
        if (primitiveType == char.class && wrapperType == Character.class) return true;
        if (primitiveType == short.class && wrapperType == Short.class) return true;
        if (primitiveType == int.class && wrapperType == Integer.class) return true;
        if (primitiveType == long.class && wrapperType == Long.class) return true;
        if (primitiveType == float.class && wrapperType == Float.class) return true;
        if (primitiveType == double.class && wrapperType == Double.class) return true;
        return false;
    }
}
