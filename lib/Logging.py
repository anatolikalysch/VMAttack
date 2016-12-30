# coding=utf-8
__author__ = 'Anatoli Kalysch'


class LoggingEngine(object):
    logger = None
    # private class
    class __Logger(object):
        def __init__(self):
            self._log = open('VMAttack.log', 'a')

        def log(self, message):
            assert(isinstance(message, str))
            message_lines = message.splitlines()
            for line in message_lines:
                self._log.write(line + '\n')

        def rm(self):
            try:
                self._log.close()
            except:
                pass
            self._log = open('VMAttack.log', 'w')

        def finalize(self):
            self._log.close()


    def __init__(self):
        # init singleton
        if not LoggingEngine.logger:
            LoggingEngine.logger = LoggingEngine.__Logger()

    def log(self, message):
        self.logger.log(message)

    def rm(self):
        self.logger.rm()
        LoggingEngine.logger = LoggingEngine.__Logger()


    def finalize(self):
        self.logger.finalize()

logEng = None

def get_log():
    global logEng
    if not logEng:
        logEng = LoggingEngine()

    return logEng

def rm_log():
    global logEng
    if not logEng:
        logEng = LoggingEngine()

    logEng.rm()