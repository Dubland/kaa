/*
 * Copyright 2015 CyberVision, Inc.
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

package org.kaaproject.kaa.server.admin.client.mvp.view.endpoint;

import com.google.common.io.BaseEncoding;
import com.google.gwt.dom.client.Style;
import com.google.gwt.user.cellview.client.DataGrid;
import org.kaaproject.avro.ui.gwt.client.widget.grid.AbstractGrid;
import org.kaaproject.kaa.common.dto.EndpointProfileDto;
import org.kaaproject.kaa.server.admin.client.mvp.data.EndpointProfileDataProvider;
import org.kaaproject.kaa.server.admin.client.util.Utils;

public class EndpointProfileGrid extends AbstractGrid<EndpointProfileDto, String> {

    public int pageSize;
    private EndpointProfileDataProvider dataProvider;

    public EndpointProfileGrid(int pageSize) {
        super(Style.Unit.PX, false, pageSize);
        this.pageSize = pageSize;
    }

    @Override
    protected float constructColumnsImpl(DataGrid<EndpointProfileDto> table) {
        float prefWidth = 0;

        prefWidth += constructStringColumn(table,
                Utils.constants.keyHash(),
                new StringValueProvider<EndpointProfileDto>() {
                    @Override
                    public String getValue(EndpointProfileDto item) {
                        return BaseEncoding.base64().encode(item.getEndpointKeyHash());
                    }
                }, 160);

        prefWidth += constructStringColumn(table,
                Utils.constants.profileSchemaVersion(),
                new StringValueProvider<EndpointProfileDto>() {
                    @Override
                    public String getValue(EndpointProfileDto item) {
                        return item.getProfileVersion() + "";
                    }
                }, 80);

        prefWidth += constructStringColumn(table,
                Utils.constants.configurationSchemaVersion(),
                new StringValueProvider<EndpointProfileDto>() {
                    @Override
                    public String getValue(EndpointProfileDto item) {
                        return item.getConfigurationVersion() + "";
                    }
                }, 80);

        prefWidth += constructStringColumn(table,
                Utils.constants.notificationSchemaVersion(),
                new StringValueProvider<EndpointProfileDto>() {
                    @Override
                    public String getValue(EndpointProfileDto item) {
                        return item.getUserNfVersion() + "";
                    }
                }, 80);

        prefWidth += constructStringColumn(table,
                Utils.constants.logSchemaVersion(),
                new StringValueProvider<EndpointProfileDto>() {
                    @Override
                    public String getValue(EndpointProfileDto item) {
                        return item.getLogSchemaVersion() + "";
                    }
                }, 80);

        return prefWidth;
    }

    @Override
    protected String getObjectId(EndpointProfileDto value) {
        return BaseEncoding.base64().encode(value.getEndpointKeyHash());
    }

    public int getPageSize() {
        return pageSize;
    }

    public EndpointProfileDataProvider getDataProvider() {
        return dataProvider;
    }

    public void setDataProvider(EndpointProfileDataProvider dataProvider) {
        this.dataProvider = dataProvider;
    }
}
