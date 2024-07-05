import datetime
class UnixTime:
    def __init__(self,utime):
        self.unix_time = utime
    def retDate(self):
        unix_time = self.unix_time
        date = datetime.datetime.utcfromtimestamp(unix_time)
        return date
