# coding=utf-8
from lib.Register import get_reg_class

__author__ = 'Anatoli Kalysch'


class Trace(list):
    def __init__(self, reg_size=64, tr=None):
        super(Trace, self).__init__()
        self.peephole = False
        self.constant_propagation = False
        self.standardization = False
        self.operand_folding = False
        self.stack_addr_propagation = False
        self.ctx_reg_size = reg_size
        if tr is not None:
            assert isinstance(tr, list)
            for line in tr:
                assert isinstance(line, Traceline)
                self.append(line)


class Traceline(object):
    def __init__(self, **kwargs):
        self._line = [kwargs.get('thread_id'),
                      kwargs.get('addr'),
                      kwargs.get('disasm'),
                      kwargs.get('ctx', ''),
                      kwargs.get('comment', '')]
        self.grade = 0

    def __eq__(self, other):
        if isinstance(other, Traceline):
            # grade is IGNORED, while things like comments and ctx are taken into account!
            return self._line == other._line
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def raise_grade(self, value=1):
        self.grade += value

    def lower_grade(self, value=1):
        self.grade -= value
        self.grade = max(0, self.grade)  # do not lower below zero to make zero the common denominator for trace line grades

    @property
    def thread_id(self):
        return self._line[0]

    @thread_id.setter
    def thread_id(self, value):
        self._line[0] = value

    @property
    def addr(self):
        return self._line[1]

    @addr.setter
    def addr(self, value):
        self._line[1] = value

    @property
    def disasm(self):
        return self._line[2]

    @disasm.setter
    def disasm(self, value):
        self._line[2] = value

    @property
    def disasm_len(self):
        return len(self.disasm)

    @property
    def ctx(self):
        return self._line[3]

    @ctx.setter
    def ctx(self, value):
        self._line[3] = value

    @property
    def comment(self):
        return self._line[4]

    @comment.setter
    def comment(self, value):
        self._line[4] = value

    def disasm_str(self):
        try:
            return '%s\t%s, %s' % (self.disasm[0], self.disasm[1], self.disasm[2])
        except:
            if self.disasm_len == 2:
                return '%s\t%s' % (self.disasm[0], self.disasm[1])
            else:
                return self.disasm[0]

    def to_str_line(self):
        return "%x %x %s\t\t%s\t\t%s" % (self.thread_id,
                                         self.addr,
                                         self.disasm_str(),
                                         ''.join(c for c in self.comment if self.comment is not None),
                                         ''.join('%s:%s ' % (c, self.ctx[c]) for c in self.ctx.keys() if isinstance(self.ctx, dict)))
    @property
    def is_mov(self):
        return self._line[2][0].__contains__('mov')

    @property
    def is_pop(self):
        return self._line[2][0].startswith('pop')

    @property
    def is_push(self):
        return self._line[2][0].startswith('push')

    @property
    def is_jmp(self):
        # returns true for conditional AND non-cond jumps
        return self._line[2][0].startswith('j')

    @property
    def is_op1_reg(self):
        try:
            return get_reg_class(self._line[2][1]) is not None
        except:
            return False

    @property
    def is_op2_reg(self):
        try:
            return get_reg_class(self._line[2][2]) is not None
        except:
            return False

    @property
    def is_comparison(self):
        return self.disasm[0].__contains__('cmp') or self.disasm[0].__contains__('test')

    @property
    def is_op1_mem(self):
        if self.disasm_len > 1:
            if self.disasm[1].startswith('[') and self.disasm[1].endswith(']'):
                return True
            elif self.disasm[1].__contains__('ptr'):
                return True
            else:
                return False
        else:
            return False

    @property
    def is_op2_mem(self):
        if self.disasm_len > 2:
            if self.disasm[2].startswith('[') and self.disasm[2].endswith(']'):
                return True
            elif self.disasm[2].__contains__('ptr'):
                return True
            else:
                return False
        else:
            return False
