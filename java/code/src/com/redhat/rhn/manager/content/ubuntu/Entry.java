package com.redhat.rhn.manager.content.ubuntu;

import com.redhat.rhn.domain.product.Tuple3;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public class Entry {
    private final String id;
    private final List<String> cves;
    private final String summary;
    private final String isummary;
    private final Instant date;
    private final String description;
    private boolean reboot;
    private final List<Tuple3<String, String, List<String>>> packages;

    Entry(String id, List<String> cves, String summary, String isummary, Instant date, String description, boolean reboot, List<Tuple3<String, String, List<String>>> packages) {
        this.id = id;
        this.cves = cves;
        this.summary = summary;
        this.date = date;
        this.description = description;
        this.reboot = reboot;
        this.packages = packages;
        this.isummary = isummary;
    }

    public String getSummary() {
        return summary;
    }

    public String getId() {
        return id;
    }

    public String getDescription() {
        return description;
    }

    public List<String> getCves() {
        return cves;
    }

    public Instant getDate() {
        return date;
    }

    public List<Tuple3<String, String, List<String>>> getPackages() {
        return packages;
    }

    public String getIsummary() {
        return isummary;
    }
}
