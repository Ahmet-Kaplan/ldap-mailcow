# Docker image
FROM python:3-alpine

RUN apk --no-cache add build-base openldap-dev python3-dev
RUN pip3 install --upgrade pip
RUN pip3 install python-ldap sqlalchemy requests environs sendmail

COPY templates ./templates
COPY api.py filedb.py syncer.py sendmail.py ./
COPY .env ./

VOLUME [ "/db" ]
VOLUME [ "/conf/dovecot" ]
VOLUME [ "/conf/sogo" ]

ENTRYPOINT [ "python3", "syncer.py" ]
