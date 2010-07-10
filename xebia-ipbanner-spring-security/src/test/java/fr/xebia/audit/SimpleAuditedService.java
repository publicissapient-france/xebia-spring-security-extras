/*
 * Copyright (c) 2010 Xebia and the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.xebia.audit;

/**
 * @author David Galichet
 */
public class SimpleAuditedService {

    @Audited(message = "save(#{args[0]}, #{args[1]}): #{returned}")
    public int save(String arg1, String arg2) {
        return 2;
    }

    @Audited(message = "save(#{args[0]}, #{args[1]}, #{args[2]}): #{returned}")
    public int save(String arg1, String arg2, String arg3) {
        throw new IllegalArgumentException("Unexpected null argument");
    }

}
