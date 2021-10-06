package com.redhat.rhn.manager.content.ubuntu;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class UbuntuErrataInfo {
    private String action;
    private List<String> cves;
    private String description;
    private String id;
    private String isummary;
    private Map<String, Release> releases;
    private String summary;
    private Instant timestamp;
    private String title;

    public Optional<String> getAction() {
        return Optional.ofNullable(action);
    }

    public Optional<String> getIsummary() {
        return Optional.ofNullable(isummary);
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public List<String> getCves() {
        return cves;
    }

    public Map<String, Release> getReleases() {
        return releases;
    }

    public String getDescription() {
        return description;
    }

    public String getId() {
        return id;
    }

    public String getSummary() {
        return summary;
    }

    public String getTitle() {
        return title;
    }

}
