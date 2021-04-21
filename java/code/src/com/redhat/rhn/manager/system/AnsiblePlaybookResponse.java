/**
 * Copyright (c) 2021 SUSE LLC
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

package com.redhat.rhn.manager.system;

import com.google.gson.annotations.SerializedName;

import org.apache.commons.lang3.builder.ToStringBuilder;

// todo find be a better place!
public class AnsiblePlaybookResponse {

    @SerializedName("fullpath")
    private String fullPath;

    @SerializedName("custom_inventory")
    private String customInventory;

    /**
     * Gets the fullPath.
     *
     * @return fullPath
     */
    public String getFullPath() {
        return fullPath;
    }

    /**
     * Gets the customInventory.
     *
     * @return customInventory
     */
    public String getCustomInventory() {
        return customInventory;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this)
                .append("fullPath", fullPath)
                .append("customInventory", customInventory)
                .toString();
    }
}
