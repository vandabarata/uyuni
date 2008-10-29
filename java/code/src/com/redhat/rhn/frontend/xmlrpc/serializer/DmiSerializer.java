/**
 * Copyright (c) 2008 Red Hat, Inc.
 *
 * This software is licensed to you under the GNU General Public License,
 * version 2 (GPLv2). There is NO WARRANTY for this software, express or
 * implied, including the implied warranties of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
 * along with this software; if not, see
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 * 
 * Red Hat trademarks are not licensed under GPLv2. No permission is
 * granted to use or replicate Red Hat trademarks that are incorporated
 * in this software or its documentation. 
 */
package com.redhat.rhn.frontend.xmlrpc.serializer;


import com.redhat.rhn.domain.server.Dmi;
import com.redhat.rhn.frontend.xmlrpc.serializer.util.SerializerHelper;

import org.apache.commons.lang.StringUtils;

import java.io.IOException;
import java.io.Writer;

import redstone.xmlrpc.XmlRpcCustomSerializer;
import redstone.xmlrpc.XmlRpcException;
import redstone.xmlrpc.XmlRpcSerializer;

/**
 * 
 * DmiSerializer
 * @version $Rev$
 * @xmlrpc.doc
 *      #struct("DMI")
 *          #prop("string", "vendor")
 *          #prop("string", "system")
 *          #prop("string", "product")
 *          #prop("string", "asset")
 *          #prop("string", "board")
 *          #prop("string", "bios_release")
 *          #prop("string", "bios_vendor")
 *          #prop("string", "bios_version")
 *      #struct_end()
 */
public class DmiSerializer implements XmlRpcCustomSerializer {

    /**
     * {@inheritDoc}
     */
    public Class getSupportedClass() {
        return Dmi.class;
    }
    /**
     * {@inheritDoc}
     */
    public void serialize(Object value, Writer output, XmlRpcSerializer builtInSerializer)
        throws XmlRpcException, IOException {
        SerializerHelper bean = new SerializerHelper(builtInSerializer);
        Dmi dmi = (Dmi) value;
        
        bean.add("vendor", StringUtils.defaultString(dmi.getVendor()));
        bean.add("system", StringUtils.defaultString(dmi.getSystem()));
        bean.add("product", StringUtils.defaultString(dmi.getProduct()));
        bean.add("asset", StringUtils.defaultString(dmi.getAsset()));
        bean.add("board", StringUtils.defaultString(dmi.getBoard()));
        bean.add("bios_release", StringUtils.defaultString(dmi.getBios().getRelease()));
        bean.add("bios_vendor", StringUtils.defaultString(dmi.getBios().getVendor()));
        bean.add("bios_version", StringUtils.defaultString(dmi.getBios().getVersion()));
        bean.writeTo(output);        
    }
    
}
