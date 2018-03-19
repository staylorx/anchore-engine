from collections import namedtuple

CheckOperation = namedtuple('CheckOperation', ['requires_rvalue', 'eval_function'])


def deprecated_operation(superceded_by=None):
    """
    Decorator to mark an operation (gate, trigger, etc) as deprecated.
    :param superceded_by: Thee name of the similar operation that supercedes the decorated one, if applicable
    :return:
    """

    def decorator(cls):
        setattr(cls, '__is_deprecated__', True)
        setattr(cls, '__superceded_by__', superceded_by)
        return cls
    return decorator
