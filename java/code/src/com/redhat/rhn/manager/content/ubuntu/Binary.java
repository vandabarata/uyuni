package com.redhat.rhn.manager.content.ubuntu;

import java.util.Optional;

public class Binary {
    private String pocket;
    private String version;
    private Optional<String> source = Optional.empty();

    public Optional<String> getSource() {
        return source;
    }

    public String getPocket() {
        return pocket;
    }

    public String getVersion() {
        return version;
    }
}
