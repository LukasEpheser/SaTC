FROM smile0304/satc
COPY --chown=satc:satc init.sh /home/satc/SaTC

ENTRYPOINT /home/satc/SaTC/init.sh
