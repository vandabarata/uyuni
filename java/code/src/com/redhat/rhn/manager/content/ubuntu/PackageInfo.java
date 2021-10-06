package com.redhat.rhn.manager.content.ubuntu;

import java.util.Optional;

public class PackageInfo {
    private String version;
    private Optional<String> description = Optional.empty();

    public String getVersion() {
        return version;
    }

    public Optional<String> getDescription() {
        return description;
    }
}
