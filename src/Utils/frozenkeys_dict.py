from collections import UserDict


# This class provides an easy interface for working with a dictionary where keys are defined only once and then
# can never be changed again via the [] operator

class FrozenKeysDict(UserDict):
    """
    A dictionary where keys are defined only once and then can never be changed again via the [] operator
    Call either 'initialize_from_dict' or 'initialize_from_kwargs' to freeze the keys
    """
    def __init__(self):
        self.__uninitialized = True
        UserDict.__init__(self)

    def initialize_from_kwargs(self, **kwargs):
        """
        Initializes the instance with the values from the arguments
        :param kwargs: any named arguments
        :return: None
        """
        if not self.__uninitialized:
            raise RuntimeError("Initialization is over")
        self.data = kwargs
        self.__uninitialized = False

    def initialize_from_dict(self, value: dict):
        """
        Initializes the instance with the values from the submitted dictionary
        :param value: the starting values
        :return: None
        """
        if not self.__uninitialized:
            raise RuntimeError("Initialization is over")
        self.data = value
        self.__uninitialized = False

    def __setitem__(self, key, value):
        if key not in self.data.keys():
            raise KeyError(f"{key} is not a valid key!")
        self.data.__setitem__(key, value)

    def __repr__(self):
        return UserDict.__repr__(self)

    def __str__(self):
        return UserDict.__str__(self)
