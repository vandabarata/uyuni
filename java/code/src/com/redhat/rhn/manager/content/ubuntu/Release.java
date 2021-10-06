package com.redhat.rhn.manager.content.ubuntu;

import java.util.Map;
import java.util.Optional;

public class Release {
    private Map<String, Urls> archs;
    private Map<String, PackageInfo> binaries;
    private Map<String, PackageInfo> sources;
    private Map<String, Binary> allbinaries;

    public Release() {
    }

    public Map<String, PackageInfo> getBinaries() {
        return binaries;
    }

    public Map<String, Binary> getAllbinaries() {
        return allbinaries;
    }

    public Map<String, PackageInfo> getSources() {
        return sources;
    }

    public Optional<Map<String, Urls>> getArchs() {
        return Optional.ofNullable(archs);
    }
}
