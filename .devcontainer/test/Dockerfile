FROM  registry.opensuse.org/opensuse/leap:15.5
RUN zypper ref -f && \
    zypper -n ar --no-gpgcheck http://download.opensuse.org/repositories/systemsmanagement:/sumaform:/tools/openSUSE_Leap_15.5/ tools && \
    zypper -n install nmap tar gzip iputils \
      gcc \
      make \
      wget \
      git \
      curl \
      ruby \
      ruby-devel \
      autoconf \
      ca-certificates-mozilla \
      automake \
      libtool \
      apache2-worker \
      cantarell-fonts \
      git-core \
      aaa_base-extras \
      zlib-devel \
      libxslt-devel \
      mozilla-nss-tools \
      postgresql14-devel \
      ruby2.5-rubygem-bundler \
      twopence \
      python-twopence \
      twopence-devel \
      twopence-shell-client \
      twopence-test-server \
      rubygem-twopence \
      chromium \
      chromedriver \
      npm \
      openssh-server \
      openssh-clients \
      hostname \
      iproute2 \
      && \
    zypper clean -a
COPY etc_pam.d_sshd /etc/pam.d/sshd
RUN mkdir /root/.ssh
COPY id_rsa_test_env /root/.ssh/id_rsa
CMD ssh-keygen -A && /usr/sbin/sshd -De
RUN curl https://raw.githubusercontent.com/uyuni-project/uyuni/master/testsuite/Gemfile -o Gemfile && bundle.ruby2.5 install && rm Gemfile
RUN mkdir -p /root/.pki/nssdb && \
    certutil -d /root/.pki/nssdb -N
COPY bashrc /root/.bashrc
RUN source /root/.bashrc
