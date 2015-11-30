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

package org.kaaproject.kaa.server.admin.client.mvp.view.endpoint;

import com.google.gwt.dom.client.Style;
import com.google.gwt.event.dom.client.ClickEvent;
import com.google.gwt.event.dom.client.ClickHandler;
import com.google.gwt.user.client.ui.Anchor;
import com.google.gwt.user.client.ui.Button;
import com.google.gwt.user.client.ui.CaptionPanel;
import com.google.gwt.user.client.ui.FlexTable;
import com.google.gwt.user.client.ui.HorizontalPanel;
import com.google.gwt.user.client.ui.Label;
import com.google.gwt.user.client.ui.Widget;
import org.kaaproject.avro.ui.gwt.client.widget.AvroWidgetsConfig;
import org.kaaproject.avro.ui.gwt.client.widget.FormPopup;
import org.kaaproject.avro.ui.gwt.client.widget.RecordFieldWidget;
import org.kaaproject.avro.ui.gwt.client.widget.SizedTextBox;
import org.kaaproject.avro.ui.gwt.client.widget.grid.AbstractGrid;
import org.kaaproject.kaa.common.dto.EndpointGroupDto;
import org.kaaproject.kaa.server.admin.client.mvp.view.EndpointProfileView;
import org.kaaproject.kaa.server.admin.client.mvp.view.base.BaseDetailsViewImpl;
import org.kaaproject.kaa.server.admin.client.mvp.view.topic.TopicGrid;
import org.kaaproject.kaa.server.admin.client.mvp.view.widget.KaaAdminSizedTextBox;
import org.kaaproject.kaa.server.admin.client.mvp.view.widget.RecordPanel;
import org.kaaproject.kaa.server.admin.client.mvp.view.widget.ServerProfileSchemasInfoListBox;
import org.kaaproject.kaa.server.admin.client.util.Utils;

import java.util.ArrayList;
import java.util.List;

public class EndpointProfileViewImpl extends BaseDetailsViewImpl implements EndpointProfileView {

    private SizedTextBox endpointKeyHash;

    private SizedTextBox userID;
    private SizedTextBox userExternalID;
    private List<Widget> userInfoList;

    private AbstractGrid<EndpointGroupDto, String> groupsGrid;
    private TopicGrid topicsGrid;

    private Anchor endpointProfSchemaName;
    private RecordPanel endpointProfForm;

    private Anchor serverProfSchemaName;
    private RecordPanel serverProfForm;

    private Button addServerSchemaButton;
    private Button deleteButton;
    private Button editButton;
    private Button saveProfileButton;

    private ServerProfileSchemasInfoListBox serverSchemasListBox;

    private RecordFieldWidget serverProfEditor;

    public EndpointProfileViewImpl() {
        super(true);
    }

    @Override
    protected String getCreateTitle() {
        return Utils.constants.endpointProfile();
    }

    @Override
    protected String getViewTitle() {
        return Utils.constants.endpointProfile();
    }

    @Override
    protected String getSubTitle() {
        return Utils.constants.endpointProfile();
    }

    @Override
    protected void initDetailsTable() {
        saveButton.removeFromParent();
        cancelButton.removeFromParent();
        requiredFieldsNoteLabel.setVisible(false);

        int row = 0;
        Label keyHashLabel = new Label(Utils.constants.endpointKeyHash());
        endpointKeyHash = new KaaAdminSizedTextBox(-1, false);
        endpointKeyHash.setWidth("100%");
        detailsTable.setWidget(row, 0, keyHashLabel);
        detailsTable.setWidget(row, 1, endpointKeyHash);

        userInfoList = new ArrayList<>();
        Label userIDLabel = new Label(Utils.constants.userId());
        userID = new KaaAdminSizedTextBox(-1, false);
        userID.setWidth("100%");
        detailsTable.setWidget(++row, 0, userIDLabel);
        detailsTable.setWidget(row, 1, userID);
        userInfoList.add(userIDLabel);
        userInfoList.add(userID);

        Label userExternalIDLabel = new Label(Utils.constants.userExternalId());
        userExternalID = new KaaAdminSizedTextBox(-1, false);
        userExternalID.setWidth("100%");
        detailsTable.setWidget(++row, 0, userExternalIDLabel);
        detailsTable.setWidget(row, 1, userExternalID);
        userInfoList.add(userExternalIDLabel);
        userInfoList.add(userExternalID);

        CaptionPanel formPanel = new CaptionPanel(Utils.constants.endpointProfile());
        FlexTable recordTable = new FlexTable();

        Label endpointProfSchemaLabel = new Label(Utils.constants.schemaName());
        endpointProfSchemaName = new Anchor();
        endpointProfSchemaName.getElement().getStyle().setCursor(Style.Cursor.POINTER);
        endpointProfSchemaName.setWidth("100%");
        recordTable.setWidget(0, 0, endpointProfSchemaLabel);
        recordTable.setWidget(0, 1, endpointProfSchemaName);

        endpointProfForm = new RecordPanel(new AvroWidgetsConfig.Builder().
                recordPanelWidth(700).createConfig(),
                Utils.constants.profile(), this, false, true);
        recordTable.setWidget(1, 0, endpointProfForm);
        recordTable.getFlexCellFormatter().setColSpan(1, 0, 2);

        formPanel.add(recordTable);
        Label endpointProfLabel = new Label(Utils.constants.endpointProfile());
        detailsTable.setWidget(++row, 0, endpointProfLabel);
        detailsTable.setWidget(++row, 0, formPanel);
        endpointProfLabel.getElement().getParentElement().getStyle().setPropertyPx("paddingBottom", 10);
        detailsTable.getFlexCellFormatter().setColSpan(row, 0, 3);
        formPanel.getElement().getParentElement().getStyle().setPropertyPx("paddingBottom", 10);

        final CaptionPanel serverFormPanel = new CaptionPanel("Server profile");
        FlexTable serverRecordTable = new FlexTable();

        Label serverProfSchemaLabel = new Label(Utils.constants.schemaName());
        serverProfSchemaName = new Anchor();
        serverProfSchemaName.getElement().getStyle().setCursor(Style.Cursor.POINTER);
        serverProfSchemaName.setWidth("100%");
        serverRecordTable.setWidget(0, 0, serverProfSchemaLabel);
        serverRecordTable.setWidget(0, 1, serverProfSchemaName);

        serverProfForm = new RecordPanel(new AvroWidgetsConfig.Builder().
                recordPanelWidth(700).createConfig(),
                Utils.constants.profile(), this, false, true);
        serverRecordTable.setWidget(1, 0, serverProfForm);
        serverRecordTable.getFlexCellFormatter().setColSpan(1, 0, 3);

        serverFormPanel.add(serverRecordTable);
        Label serverProfLabel = new Label("Server profile");
        detailsTable.setWidget(++row, 0, serverProfLabel);
        detailsTable.setWidget(++row, 0, serverFormPanel);
        serverProfLabel.getElement().getParentElement().getStyle().setPropertyPx("paddingBottom", 10);
        detailsTable.getFlexCellFormatter().setColSpan(row, 0, 2);
        serverFormPanel.getElement().getParentElement().getStyle().setPropertyPx("paddingBottom", 10);

        HorizontalPanel buttonsPanel = new HorizontalPanel();
        buttonsPanel.setSpacing(15);

        addServerSchemaButton = new Button("Add schema");
        deleteButton = new Button("Delete");
        editButton = new Button("Edit");
        buttonsPanel.add(addServerSchemaButton);
        buttonsPanel.add(deleteButton);
        buttonsPanel.add(editButton);
        detailsTable.setWidget(++row, 0, buttonsPanel);
        buttonsPanel.getElement().getParentElement().getStyle().setPropertyPx("paddingBottom", 10);

        final FormPopup serverProfPopup = new FormPopup();
        saveProfileButton = new Button("Save");
        serverProfPopup.addButton(saveProfileButton);
        Button closeServerProfPopupButton = new Button(Utils.constants.close());
        serverProfPopup.addButton(closeServerProfPopupButton);

        closeServerProfPopupButton.addClickHandler(new ClickHandler() {
            @Override
            public void onClick(ClickEvent clickEvent) {
                serverProfPopup.hide();
            }
        });

        FlexTable popupFlexTable = new FlexTable();
        final HorizontalPanel listBoxPanel = new HorizontalPanel();
        listBoxPanel.setSpacing(15);
        Label serverProfListLabel = new Label("Profile schema");
        serverSchemasListBox = new ServerProfileSchemasInfoListBox();
        serverSchemasListBox.getElement().getStyle().setPropertyPx("minWidth", 100);
        listBoxPanel.add(serverProfListLabel);
        listBoxPanel.add(serverSchemasListBox);
        popupFlexTable.setWidget(0, 0, listBoxPanel);
        serverProfListLabel.getElement().getParentElement().getStyle().setPropertyPx("paddingBottom", 10);

        CaptionPanel recordPanel = new CaptionPanel("Server profile");
        serverProfEditor = new RecordFieldWidget(new AvroWidgetsConfig.Builder().recordPanelWidth(700)
                .createConfig());
        serverProfEditor.getElement().getStyle().setPropertyPx("minHeight", 400);
        recordPanel.add(serverProfEditor);
        recordPanel.getElement().getStyle().setPropertyPx("minWidth", 700);
        popupFlexTable.setWidget(1, 0, recordPanel);
        popupFlexTable.getFlexCellFormatter().setColSpan(1, 0, 2);
        serverProfPopup.add(popupFlexTable);

        addServerSchemaButton.addClickHandler(new ClickHandler() {
            @Override
            public void onClick(ClickEvent clickEvent) {
                listBoxPanel.setVisible(true);
                serverProfPopup.center();
                serverProfPopup.show();
            }
        });

        saveProfileButton.addClickHandler(new ClickHandler() {
            @Override
            public void onClick(ClickEvent clickEvent) {
                serverProfPopup.hide();
            }
        });

        editButton.addClickHandler(new ClickHandler() {
            @Override
            public void onClick(ClickEvent clickEvent) {
                listBoxPanel.setVisible(false);
                serverProfPopup.center();
                serverProfPopup.show();
            }
        });

        groupsGrid = new EndpointGroupGrid(true);
        groupsGrid.setSize("700px", "200px");
        Label groupsLabel = new Label(Utils.constants.endpointGroups());
        detailsTable.setWidget(++row, 0, groupsLabel);
        groupsLabel.getElement().getParentElement().getStyle().setPropertyPx("paddingBottom", 10);
        detailsTable.setWidget(++row, 0, groupsGrid);
        groupsGrid.getElement().getParentElement().getStyle().setPropertyPx("paddingBottom", 10);
        detailsTable.getFlexCellFormatter().setColSpan(row, 0, 3);

        topicsGrid = new TopicGrid(false, true);
        topicsGrid.setSize("700px", "200px");
        Label topicLabel = new Label(Utils.constants.subscribedOnNfTopics());
        topicLabel.addStyleName(Utils.kaaAdminStyle.bAppContentTitleLabel());
        detailsTable.setWidget(++row, 0, topicLabel);
        detailsTable.getFlexCellFormatter().setColSpan(row, 0, 3);
        topicLabel.getElement().getParentElement().getStyle().setPropertyPx("paddingBottom", 10);
        detailsTable.setWidget(++row, 0, topicsGrid);
        detailsTable.getFlexCellFormatter().setColSpan(row, 0, 3);
        topicsGrid.getElement().getParentElement().getStyle().setPropertyPx("paddingBottom", 10);
    }

    protected AbstractGrid<EndpointGroupDto, String> createGrid() {
        return new EndpointGroupGrid();
    }

    @Override
    protected void resetImpl() {
        endpointKeyHash.setValue("");
        userID.setValue("");
        userExternalID.setValue("");
        endpointProfSchemaName.setText("");
        serverProfSchemaName.setText("");
        serverSchemasListBox.reset();

        addServerSchemaButton.setEnabled(false);
        deleteButton.setEnabled(false);
        editButton.setEnabled(false);
        saveProfileButton.setEnabled(false);

        endpointProfForm.getRecordWidget().clear();
        serverProfForm.getRecordWidget().clear();
        serverProfEditor.clear();
    }

    @Override
    protected boolean validate() {
        return false;
    }

    @Override
    public SizedTextBox getKeyHash() {
        return endpointKeyHash;
    }

    @Override
    public SizedTextBox getUserID() {
        return userID;
    }

    @Override
    public SizedTextBox getUserExternalID() {
        return userExternalID;
    }

    @Override
    public List<Widget> getUserInfoList() {
        return userInfoList;
    }

    public Anchor getEndpointProfSchemaName() {
        return endpointProfSchemaName;
    }

    public RecordPanel getEndpointProfForm() {
        return endpointProfForm;
    }

    @Override
    public Anchor getServerProfSchemaName() {
        return serverProfSchemaName;
    }

    @Override
    public RecordPanel getServerProfForm() {
        return serverProfForm;
    }

    @Override
    public Button getAddServerSchemaButton() {
        return addServerSchemaButton;
    }

    @Override
    public Button getDeleteButton() {
        return deleteButton;
    }

    @Override
    public Button getEditButton() {
        return editButton;
    }

    @Override
    public Button getSaveProfileButton() {
        return saveProfileButton;
    }

    @Override
    public AbstractGrid<EndpointGroupDto, String> getGroupsGrid() {
        return groupsGrid;
    }

    @Override
    public TopicGrid getTopicsGrid() {
        return topicsGrid;
    }

    @Override
    public RecordFieldWidget getServerProfEditor() {
        return serverProfEditor;
    }

    @Override
    public ServerProfileSchemasInfoListBox getServerSchemasListBox() {
        return serverSchemasListBox;
    }
}
