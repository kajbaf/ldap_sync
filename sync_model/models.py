# sync_model/models.py
from django.db import models
from datetime import datetime
import json

class user_data(models.Model):
     uid = models.CharField(max_length=255, unique=True)
     attrs = models.TextField()
     date = models.DateField()
##     timestamp = models.DateTimeField(default=datetime.now, blank=False)
     bak = models.TextField()
     state = models.CharField(max_length=3)
     ad_manager = models.CharField(max_length=1024)

##     def update_ts(self):
##         self.timestamp = datetime.now()
     def piggy_bak(self, sync_date):
         if not self.bak:
             self.bak = sync_date
         elif not sync_date in self.bak:
             self.bak += ',' + sync_date
     def set_attrs(self, data):
         try:
             self.attrs = json.dumps(data)
         except Exception as e:
             print 'ERROR in data'
             print data
             for k, v in data.iteritems():
                  print k, v
             print e
             raise e
     def get_attrs(self, attr=None):
         attrs = json.loads(self.attrs)
         if attr:
             return attrs[attr]
         return attrs
     def __str__(self):
         return self.uid
     def __repr__(self):
         return self.uid
##     def save(self, *args, **kwargs):
##         self.timestamp = datetime.now()
##         super(user_data, self).save(*args, **kwargs) # Call the "real" save() method.

