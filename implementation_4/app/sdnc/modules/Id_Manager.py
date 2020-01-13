class IdManagerException(Exception): pass

class IdManager(object):

  def __init__(self, n):
    self.max = n
    self.ids = set(range(0, n))

  def get_id(self):
    try:
      return self.ids.pop()
    except KeyError:
      raise IdManagerException("no available ids")

  def free_id(self, n):
    if n > self.max:
      raise IdManagerException("id %d out of range (max %d)" % (n, self.max))

    self.ids.add(n)
