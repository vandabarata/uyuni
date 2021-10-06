package com.redhat.rhn.manager.content.ubuntu;

import com.google.common.reflect.TypeToken;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import com.mockobjects.util.NotImplementedException;
import com.redhat.rhn.common.util.TimeUtils;
import com.redhat.rhn.common.util.http.HttpClientAdapter;
import com.redhat.rhn.domain.channel.Channel;
import com.redhat.rhn.domain.channel.ChannelFactory;
import com.redhat.rhn.domain.errata.*;
import com.redhat.rhn.domain.product.SUSEProductFactory;
import com.redhat.rhn.domain.product.Tuple3;
import com.redhat.rhn.domain.rhnpackage.Package;
import com.redhat.rhn.domain.rhnpackage.PackageArch;
import com.redhat.rhn.domain.rhnpackage.PackageEvr;
import com.redhat.rhn.domain.rhnpackage.PackageFactory;
import com.suse.manager.reactor.utils.OptionalTypeAdapterFactory;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpGet;
import org.apache.log4j.Logger;

import java.io.IOException;
import java.io.InputStreamReader;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class UbuntuErrataManager {

    private static Logger LOG = Logger.getLogger(UbuntuErrataManager.class);

    private static String archToPackageArchLabel(String arch) {
        switch (arch) {
            case "all": return "all-deb";
            case "source": return "src";
            case "amd64": return "amd64-deb";
            case "arm64": return "arm64-deb";
            //TODO: find right arch
            case "armel": return "arm64-deb";
            case "armhf": return "armhf-deb";
            case "sparc": return "sparc-deb";
            case "i386": return "i386-deb";
            //TODO: find right arch
            case "riscv64": return "all-deb";
            //TODO: find right arch
            case "ppc64el": return "powerpc-deb";
            //TODO: find right arch
            case "s390x": return "s390-deb";
            case "powerpc": return "powerpc-deb";
            default: return "";
        }
    }

    public static Map<String, UbuntuErrataInfo> downloadUbuntuErrata() throws IOException {
        String jsonDBUrl = "https://usn.ubuntu.com/usn-db/database.json";
        HttpClientAdapter httpClient = new HttpClientAdapter();
        HttpGet httpGet = new HttpGet(jsonDBUrl);
        LOG.info("download ubuntu errata start");
        HttpResponse httpResponse = httpClient.executeRequest(httpGet);
        if (httpResponse.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
            InputStreamReader content = new InputStreamReader(httpResponse.getEntity().getContent());
            TypeToken<Map<String, UbuntuErrataInfo>> type =
                    new TypeToken<Map<String, UbuntuErrataInfo>>(){};
            Map<String, UbuntuErrataInfo> errataInfo = GSON.fromJson(content, type.getType());
            LOG.info("download ubuntu errata end");
            return errataInfo;
        }
        else {
            throw new IOException("error downloading " + jsonDBUrl + " status code " + httpResponse.getStatusLine().getStatusCode());
        }
    }

    private static final Gson GSON = new GsonBuilder()
            .registerTypeAdapterFactory(new OptionalTypeAdapterFactory())
            .registerTypeAdapter(Instant.class, new TypeAdapter<Instant>() {
                @Override
                public void write(JsonWriter jsonWriter, Instant instant) throws IOException {
                    throw new NotImplementedException();
                }

                @Override
                public Instant read(JsonReader jsonReader) throws IOException {
                    double d = jsonReader.nextDouble();
                    long seconds = (long)d;
                    long n = (long)((d - seconds) * 1e9);
                    return Instant.ofEpochSecond(seconds, n);
                }
            })
            .create();

    public static List<Entry> getUbuntuErrataInfo() throws IOException {
        Map<String, UbuntuErrataInfo> errataInfo = downloadUbuntuErrata();

        return errataInfo.entrySet().stream().map(info -> {
            String description = info.getValue().getDescription().length() > 4000 ?
                    info.getValue().getDescription().substring(0, 4000) :
                    info.getValue().getDescription();
            boolean reboot = info.getValue().getAction().map(a -> a.contains("you need to reboot")).orElse(false);
            List<Tuple3<String, String, List<String>>> packageData = info.getValue().getReleases().entrySet().stream().flatMap(release -> {
                return release.getValue().getBinaries().entrySet().stream().flatMap(binary -> {
                    String name = binary.getKey();
                    String version = binary.getValue().getVersion();

                    List<String> archs = release.getValue().getArchs().stream().flatMap(m -> m.entrySet().stream()).flatMap(a -> {
                        String arch = a.getKey();
                        boolean hasArchPkg = a.getValue().getUrls().entrySet().stream().anyMatch(b -> {
                            String url = b.getKey();
                            return url.endsWith("/" + name + "_" + version + "_" + arch + ".deb");
                        });
                        if (hasArchPkg) {
                            return Stream.of(arch);
                        } else {
                            return Stream.empty();
                        }
                    }).collect(Collectors.toList());
                    return Stream.of(new Tuple3<>(name, version, archs));
                });
            }).collect(Collectors.toList());

            return new Entry(
                    info.getValue().getId(),
                    info.getValue().getCves(),
                    info.getValue().getSummary(),
                    info.getValue().getIsummary().orElse("-"),
                    info.getValue().getTimestamp(),
                    description,
                    reboot,
                    packageData);
        }).collect(Collectors.toList());
    }

    public static void processUbuntuErrataByIds(Set<Long> channelIds) throws IOException {
        processUbuntuErrata(channelIds.stream()
                .map(cid -> ChannelFactory.lookupById(cid))
                .collect(Collectors.toSet()));
    }

    public static void processUbuntuErrata(Set<Channel> channels) throws IOException {
        List<Entry> ubuntuErrataInfo = getUbuntuErrataInfo();

        Map<Channel, Set<Package>> ubuntuChannels = channels.stream()
                .flatMap(s -> s.getSuseProductChannels().stream().map(e -> e.getChannel()))
                .collect(Collectors.toMap(c -> c, c -> c.getPackages()));

        List<String> uniqueCVEs = ubuntuErrataInfo.stream()
                .flatMap(e -> e.getCves().stream().filter(c -> c.startsWith("CVE-")))
                .distinct()
                .collect(Collectors.toList());

        Map<String, Cve> cveByName = TimeUtils.logTime(LOG, "looking up " +  uniqueCVEs.size() + " CVEs",
                () -> uniqueCVEs.stream().map(e -> {
                    return CveFactory.lookupOrInsertByName(e);
                }).collect(Collectors.toMap(e -> e.getName(), e -> e)));

        TimeUtils.logTime(LOG, "writing " + ubuntuErrataInfo.size() + " erratas to db", () -> {
            ubuntuErrataInfo.stream().map(entry -> {

                Errata errata = Optional.ofNullable(ErrataFactory.lookupByAdvisoryAndOrg(entry.getId(), null))
                        .orElseGet(Errata::new);
                errata.setAdvisory(entry.getId());
                errata.setAdvisoryName(entry.getId());
                errata.setAdvisoryStatus(AdvisoryStatus.STABLE);
                errata.setAdvisoryType(ErrataFactory.ERRATA_TYPE_SECURITY);
                errata.setIssueDate(Date.from(entry.getDate()));
                errata.setUpdateDate(Date.from(entry.getDate()));
                String[] split = entry.getId().split("-", 2);
                errata.setAdvisoryRel(Long.parseLong(split[1]));
                errata.setProduct("Ubuntu");
                errata.setSolution("-");
                errata.setSynopsis(entry.getIsummary());
                Set<Cve> cves = entry.getCves().stream()
                        .filter(c -> c.startsWith("CVE-"))
                        .map(cveByName::get)
                        .collect(Collectors.toSet());
                errata.setCves(cves);
                errata.setDescription(entry.getDescription());

                Map<Channel, Set<Package>> matchingPackagesByChannel =
                        TimeUtils.logTime(LOG, "matching packages for " + entry.getId(), () -> {
                            return ubuntuChannels.entrySet().stream().collect(Collectors.toMap(e -> e.getKey(), c -> {

                                return c.getValue().stream().filter(p -> {

                                    return entry.getPackages().stream().anyMatch(e -> {

                                        PackageEvr packageEvr = PackageEvr.parseDebian(e.getB());
                                        return e.getC().stream().anyMatch(arch -> {
                                            return p.getPackageName().getName().equals(e.getA()) &&
                                                    p.getPackageArch().getLabel().equals(archToPackageArchLabel(arch)) &&
                                                    p.getPackageEvr().getVersion().equals(packageEvr.getVersion()) &&
                                                    p.getPackageEvr().getRelease().equals(packageEvr.getRelease()) &&
                                                    Optional.ofNullable(p.getPackageEvr().getEpoch())
                                                            .equals(Optional.ofNullable(packageEvr.getEpoch())) &&
                                                    p.getPackageEvr().getPackageType().equals(packageEvr.getPackageType());
                                        });

                                    });

                                }).collect(Collectors.toSet());
                            }));
                        });

                Set<Package> packages = matchingPackagesByChannel.entrySet().stream()
                        .flatMap(e -> e.getValue().stream())
                        .collect(Collectors.toSet());

                errata.setPackages(packages);

                Set<Channel> matchingChannels = matchingPackagesByChannel.entrySet().stream()
                        .filter(c -> !c.getValue().isEmpty())
                        .map(c -> c.getKey())
                        .collect(Collectors.toSet());

                errata.setChannels(matchingChannels);

                return errata;
            }).forEach(ErrataFactory::save);
        });
    }
}
