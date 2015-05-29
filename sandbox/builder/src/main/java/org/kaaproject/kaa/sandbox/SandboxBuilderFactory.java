/*
 * Copyright 2014 CyberVision, Inc.
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
package org.kaaproject.kaa.sandbox;

import java.io.File;
import java.net.URL;

import org.kaaproject.kaa.sandbox.docker.DockerSandboxBuilder;
import org.kaaproject.kaa.sandbox.vbox.VboxSandboxBuilder;

public class SandboxBuilderFactory {

    public static SandboxBuilder createSandboxBuilder(File basePath,
            BoxType boxType, 
            OsType osType, 
            URL baseImageUrl, 
            String boxName,
            File imageOutputFile, 
            int sshFowardPort,
            int webAdminForwardPort) throws Exception {
        
        switch (boxType) {
        case VBOX:
            return new VboxSandboxBuilder(basePath, osType, baseImageUrl, boxName, imageOutputFile, sshFowardPort, webAdminForwardPort);
        case DOCKER:
            return new DockerSandboxBuilder(basePath, osType, boxName, sshFowardPort, webAdminForwardPort);
            default:
                throw new RuntimeException("Unimplemented box type: " + boxType.name());
        }
        
    }
    
}
