FROM python
RUN pip install motor sanic sanic-prometheus sanic_wtf
ADD lease.py /
CMD /lease.py
