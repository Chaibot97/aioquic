from gf256_table import gf256_mul_table, gf256_inv_table
import typing

class GF256Number:
  def __init__(self, n):
    self.n = n

  def __add__(self, other):
    assert type(self) == type(other)
    return GF256Number(self.n ^ other.n)

  def __sub__(self, other):
    assert type(self) == type(other)
    return self + other

  def __mul__(self, other):
    assert type(self) == type(other)
    return GF256Number(gf256_mul_table[self.n][other.n])

  def __truediv__(self, other):
    assert type(self) == type(other)
    return GF256Number(gf256_mul_table[self.n][gf256_inv_table[other.n]])

  def __lt__(self,other):
    assert type(self) == type(other)
    return self.n<other.n

  def __gt__(self,other):
    assert type(self) == type(other)
    return self.n>other.n

  def __eq__(self, other):
    if type(self) == type(other):
      return self.n == other.n
    elif type(other)==type(0):
      return self.n == other
    return False

  def __str__(self):
    return str(self.n)

class GF256Vector:
  def __init__(self, v: [int], padding:int = 0, trailing:int = 0):
    self.v = [GF256Number(0) for i in range(padding)] + [GF256Number(n) for n in v] + [GF256Number(0) for i in range(trailing)]

  def pad(self, padding:int):
    self.v = [GF256Number(0) for i in range(padding)] + self.v

  def augment(self, padding:int):
    self.v = self.v + [GF256Number(0) for i in range(padding)]

  def scale(self, c: GF256Number):
    res = GF256Vector([])
    res.v = [c * n for n in self.v]
    return res

  def __add__(self, other):
    length = min(len(self.v),len(other.v))
    res = GF256Vector([])
    res.v = [self.v[i] + other.v[i] for i in range(length)]
    return res

  def __sub__(self, other):
    length = min(len(self.v),len(other.v))
    res = GF256Vector([])
    res.v = [self.v[i] - other.v[i] for i in range(length)]
    return res

  def dot(self, other) -> GF256Number:
    length = min(len(self.v),len(other.v))
    res = GF256Number(0)
    for i in range(length):
      res = res + self.v[i]*other.v[i]
    return res

  def cmpAt(self, other, index:int):
    if self.v[index] < other.v[index]:
      return -1
    elif self.v[index] > other.v[index]:
      return 1
    return 0

  def toListOfInt(self):
    return [n.n for n in self.v]

  def __getitem__(self, index):
    return self.v[index]

  def __setitem__(self, index, value):
    self.v[index]= value

  def __str__(self):
    return ' '.join([str(x) for x in self.v])

def GF256LinearCombination(vectors: [bytearray], coefficients: [int]) -> bytearray:
  max_len = max([len(vector) for vector in vectors])
  vectors = [GF256Vector(vector, max_len - len(vector)) for vector in vectors]

  res = GF256Vector([0] * max_len)

  for v, c in zip(vectors, coefficients):
    res += v.scale(GF256Number(c))

  return bytearray(res.toListOfInt())

def GF256PacketRecover(repair_vectors: [bytearray],
                       data_vectors: [bytearray],
                       coefficients: [int],
                       lost_coefficients: [int]) -> [bytearray]:
  max_len = max([len(vector) for vector in data_vectors])
  max_len = max(max_len, len(repair_vectors[0]))

  repair_vectors = [GF256Vector(vector) for vector in repair_vectors]
  data_vectors = [GF256Vector(vector, trailing=max_len - len(vector)) for vector in data_vectors]
  coefficients = [GF256Vector(coefficient) for coefficient in coefficients]
  lost_coefficients = [GF256Vector(coefficient) for coefficient in lost_coefficients]

  # minus received packets from repair packets
  for i in range(len(repair_vectors)):
    for v, c in zip(data_vectors, coefficients[i]):
      repair_vectors[i] -= v.scale(c)

  gf256_system = GF256System()
  for i in range(len(repair_vectors)):
    gf256_system.addEq(lost_coefficients[i], chr(97+i) ,repair_vectors[i])

  gf256_system.gaussElimination()
  gf256_system.solve()

  recovered_packets = [bytearray(con.toListOfInt()) for con in gf256_system.cons]
  return recovered_packets


class GF256System:
  def __init__(self):
    self.vars = set()
    self.eqs = []
    self.cons = []

  def addEq(self, eq, var, con):
    self.eqs.append(eq)
    self.cons.append(con)
    self.vars.add(var)

  def isSolvable(self) -> bool:
    return len(self.vars) == len(self.eqs)

  def swapRows(self, i, j):
    self.eqs[i], self.eqs[j] = self.eqs[j], self.eqs[i]
    self.cons[i], self.cons[j] = self.cons[j], self.cons[i]

  def sortSystem(self):
    n_eq = len(self.eqs)
    for i in range(n_eq):
      j_max = i
      for j in range(i+1,n_eq):
        if self.eqs[j_max].cmpAt(self.eqs[j], i) < 0:
          j_max = j

      self.swapRows(i,j_max)

  def __str__(self):
    res = ''
    for i in range(len(self.eqs)):
      res += ' + '.join([str(x)+str(sorted(self.vars)[k]) for k, x in enumerate(self.eqs[i])])
      res += ' = ' + str(self.cons[i]) + '\n'
    return res

  def gaussElimination(self):
    r = 0
    c = 0

    m = len(self.eqs)
    n = len(self.vars)
    while r < m and c < n:
      i_max = 0
      for i in range(r, m):
        if self.eqs[i].cmpAt(self.eqs[i_max], c) > 0:
          i_max = i

      if self.eqs[i_max][c] == 0:
          c += 1
      else:
          self.swapRows(r,i_max)
          for i in range(r+1, m):
            f = self.eqs[i][c] / self.eqs[r][c]
            # print(self.eqs[i][c],self.eqs[r][c], f)
            self.eqs[i][c] = GF256Number(0)
            # for j in range(c + 1, n):
            #   self.eqs[i][j] = self.eqs[i][j] - self.eqs[r][j] * f
            self.eqs[i] -= self.eqs[r].scale(f)
            self.cons[i] -= self.cons[r].scale(f)

          r += 1
          c += 1

  def solve(self):
    for r in range(len(self.eqs) - 1, -1, -1):
      for c in range(len(self.eqs) - 1, r, -1):
        self.cons[r] -= self.cons[c].scale(self.eqs[r][c])
        self.eqs[r][c] = GF256Number(0)
      self.cons[r] = self.cons[r].scale(GF256Number(1) /self.eqs[r][r])
      self.eqs[r][r] = GF256Number(1)



def symbol_add_scaled(symbol1: [GF256Number], coef: GF256Number, symbol2: [GF256Number]):
  length = min(len(symbol1),len(symbol2))
  for i in range(length):
    symbol1[i] += coef * symbol2[i]

def symbol_sub_scaled(symbol1: [GF256Number], coef: GF256Number, symbol2: [GF256Number]):
  symbol_add_scaled(symbol1, coef, symbol2)

def symbol_mul(symbol: [int], coef: int):
  for i in range(len(symbol)):
    symbol[i] = symbol[i]*coef

def symbol_div(symbol: [int], coef: int):
  for i in range(len(symbol)):
    symbol[i] = symbol[i]/coef

def symbol_cmp(symbol1: [int], symbol2: [int]) -> int:
  if len(symbol1) > len(symbol2):
    return 1
  elif len(symbol1) < len(symbol2):
    return -1

  for i in range(len(symbol1)):
    if symbol1[i] != GF256Number(0) and symbol2[i] == GF256Number(0) :
      return 1
    elif symbol1[i] == GF256Number(0)  and symbol2[i] != GF256Number(0) :
      return -1

  return 0

def symbol_is_zero(symbol: [int]) -> bool:
  for s in symbol:
    if s != GF256Number(0):
      return False
  return True


if __name__ == "__main__":
  a = GF256Number(int('0b01010011', 2))
  b = GF256Number(int('0b11001010', 2))
  z = GF256Number(int('0b0', 2))

  c = GF256Number(int('0b10011001', 2)) # a+b=c
  assert c == a+b
  assert a == c-b

  d = GF256Number(int('0b10001111', 2)) # a*b=d
  assert d == a*b
  assert d == b*a
  assert a == d/b
  assert b == d/a

  s1 = [a,a]
  s2 = [b,b]
  s3 = [c,c]
  symbol_add_scaled(s1, GF256Number(1), s2)
  assert s1 == s3
  symbol_sub_scaled(s1, GF256Number(1), s2)
  assert s1 == [a,a]

  assert symbol_cmp([z],[a]) == -1
  assert symbol_is_zero([z])

  k = GF256Vector([1, 2, 3])
  kk = GF256Vector([3, 2, 1])

  assert k.dot(kk) == 4

  # testing packet recovery
  a = bytearray("abc", 'utf-8')
  b = bytearray("xyz", 'utf-8')
  c = bytearray("jkl", 'utf-8')
  coef1 = [2, 5, 8]
  coef2 = [3, 7, 1]

  repair1 = GF256LinearCombination([a, b ,c], coef1)
  repair2 = GF256LinearCombination([a, b ,c], coef2)

  recovered_packets = GF256PacketRecover([repair1, repair2], [a ], [[2], [3]], [[5, 8], [7, 1]])
  assert b == recovered_packets[0]
  assert c == recovered_packets[1]