import logging
try:
    from ethereum.slogging import get_logger, configure
except ImportError:
    print 'could not import slogging'
    # patch logging to support kargs
    _log_orig = logging.Logger._log

    def _kargs_log(self, level, msg, args, exc_info=None, extra=None, **kargs):
        msg += ' ' + ' '.join('%s=%r' % (k, v) for k, v in kargs.items())
        _log_orig(self, level, msg, args, exc_info, extra)
    logging.Logger._log = _kargs_log
    get_logger = logging.getLogger

if __name__ == '__main__':
    logging.basicConfig()
    log = get_logger('test')
    log.warn('miner.new_block', block_hash='abcdef123', nonce=2234231)
