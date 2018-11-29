FROM python:3
ADD server.py /
ADD requirements.txt /
RUN pip install -r requirements.txt
CMD python server.py