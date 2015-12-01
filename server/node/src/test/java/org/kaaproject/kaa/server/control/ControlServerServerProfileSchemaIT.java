/*
 * Copyright 2014-2015 CyberVision, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.kaaproject.kaa.server.control;

import org.junit.Assert;
import org.junit.Test;
import org.kaaproject.kaa.common.dto.ApplicationDto;
import org.kaaproject.kaa.common.dto.ServerProfileSchemaDto;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 *
 */
public class ControlServerServerProfileSchemaIT extends AbstractTestControlServer {

    /**
     * Test create server profile schema
     *
     * @throws Exception
     */
    @Test
    public void testCreateServerProfileSchema() throws Exception{
        ServerProfileSchemaDto serverProfileSchema = createServerSchema();
        Assert.assertFalse(strIsEmpty(serverProfileSchema.getId()));
    }

    /**
     * Test get server profile schema.
     *
     * @throws Exception the exception
     */
    @Test
    public void testGetServerProfileSchema() throws Exception {
        ServerProfileSchemaDto profileSchema = createServerSchema();

        ServerProfileSchemaDto storedServerProfileSchema = client.getServerProfileSchema(profileSchema.getId());

        Assert.assertNotNull(storedServerProfileSchema);
        assertProfileSchemasEquals(profileSchema, storedServerProfileSchema);
    }

    /**
     * Test get server profile schemas by application id.
     *
     * @throws Exception the exception
     */
    @Test
    public void testServerGetProfileSchemasByApplicationId() throws Exception {

        List<ServerProfileSchemaDto> profileSchemas  = new ArrayList<>(11);
        ApplicationDto application = createApplication(tenantAdminDto);

        loginTenantDeveloper(tenantDeveloperDto.getUsername());

        List<ServerProfileSchemaDto> defaultServerProfileSchemas = client.getServerProfileSchemas(application.getId());
        profileSchemas.addAll(defaultServerProfileSchemas);

        for (int i=0;i<10;i++) {
            ServerProfileSchemaDto profileSchema = createServerSchema(application.getId());
            profileSchemas.add(profileSchema);
        }

        Collections.sort(profileSchemas, new IdComparator());

        List<ServerProfileSchemaDto> storedServerProfileSchemas = client.getServerProfileSchemas(application.getId());

        Collections.sort(storedServerProfileSchemas, new IdComparator());

        Assert.assertEquals(profileSchemas.size(), storedServerProfileSchemas.size());
        for (int i=0;i<profileSchemas.size();i++) {
            ServerProfileSchemaDto profileSchema = profileSchemas.get(i);
            ServerProfileSchemaDto storedServerSchema = storedServerProfileSchemas.get(i);
            assertProfileSchemasEquals(profileSchema, storedServerSchema);
        }
    }

    /**
     * Test update server profile schema.
     *
     * @throws Exception the exception
     */
    @Test
    public void testUpdateServerProfileSchema() throws Exception {
        ServerProfileSchemaDto profileSchema = createServerSchema();

        profileSchema.getSchemaDto().setName("Test Schema 2");
        profileSchema.getSchemaDto().setDescription("Test Desc 2");

        ServerProfileSchemaDto updatedProfileSchema = client
                .editServerProfileSchema(profileSchema);

        assertProfileSchemasEquals(profileSchema, updatedProfileSchema);
    }


    /**
     * Assert server profile schemas equals.
     *
     * @param profileSchema the profile schema
     * @param storedProfileSchema the stored profile schema
     */
    private void assertProfileSchemasEquals(ServerProfileSchemaDto profileSchema, ServerProfileSchemaDto storedProfileSchema) {
        Assert.assertEquals(profileSchema.getId(), storedProfileSchema.getId());
        Assert.assertEquals(profileSchema.getSchemaDto().getId(), storedProfileSchema.getSchemaDto().getId());
        Assert.assertEquals(profileSchema.getApplicationId(), storedProfileSchema.getApplicationId());
        Assert.assertEquals(profileSchema.getSchemaDto().getApplicationId(), storedProfileSchema.getSchemaDto().getApplicationId());
        Assert.assertEquals(profileSchema.getSchemaDto().getBody(), storedProfileSchema.getSchemaDto().getBody());
        Assert.assertEquals(profileSchema.getSchemaDto().getName(), storedProfileSchema.getSchemaDto().getName());
        Assert.assertEquals(profileSchema.getSchemaDto().getDescription(), storedProfileSchema.getSchemaDto().getDescription());
        Assert.assertEquals(profileSchema.getCreatedTime(), storedProfileSchema.getCreatedTime());
        Assert.assertEquals(profileSchema.getSchemaDto().getCreatedTime(), storedProfileSchema.getSchemaDto().getCreatedTime());
    }
}
