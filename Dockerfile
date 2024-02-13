# Use Ubuntu as the base image
FROM ubuntu:latest

# Install SSH server and sudo package
RUN apt-get update && \
    apt-get install -y openssh-server sudo vim nano && \
    mkdir /var/run/sshd

# Set a password for the root user
RUN echo 'root:123' | chpasswd

# Create a new user "Bitty", set password, and add to 'sudo' group
RUN useradd -m bitty && \
    echo 'bitty:123' | chpasswd

# Create a new user "dave" with UID 0, set password, and add to 'sudo' group
RUN useradd -m -u 0 -o -G sudo dave && \
    echo 'dave:davepass' | chpasswd

# Create a sample log file in /root
RUN touch /root/log_file.txt && \
    echo "Sample log content" > /root/log_file.txt

# Configure specific sudo privilege for bitty
# Correcting the sudoers configuration
RUN echo 'bitty ALL=(root) NOPASSWD: /bin/less /root/log_file.txt' > /etc/sudoers.d/bitty && \
    chmod 0440 /etc/sudoers.d/bitty

# Optional: Configure SSHD (Enabling these as per your earlier Dockerfile comment)
RUN echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config && \
    echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config

# Copy the 'audit' file to bitty's home directory and ensure it's executable maybe not needed after all idk
COPY audit /home/bitty/audit
RUN chmod u+s /home/bitty/audit && \
    chmod a+x /home/bitty/audit

# USER bitty

# Run audit bin
CMD ["tail", "-f", "/dev/null"]
# docker build -t audit .                                                                                                                                                                                         0.0s
# bitis@Workstation ~/s/netsec> docker run -d --name audit-container test
# docker stop audit-container
# docker rm audit-container
# docker system prune


