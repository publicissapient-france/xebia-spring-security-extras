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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * @author David Galichet
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = "classpath:fr/xebia/audit/test-springContext.xml")
public class AuditAspectTest {

    private Logger logger = LoggerFactory.getLogger(AuditAspectTest.class);

    @Autowired
    private SimpleAuditedService simpleAuditedService;

    @Before
    public void init() { }

    @Test
    public void testSaveMethod() {
        simpleAuditedService.save("foo", "bar");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSaveMethodThrowNPE() {
        simpleAuditedService.save("foo", "bar", "badArg");
    }

}
