import os
import configparser
from abc import ABCMeta
from typing import Any

class Singleton(ABCMeta):
    """
    
    This class is a standard implementation of the Single Pattern
    (Note: Has not been tested for Thread Saftey)

    """

    _instances = {}

    def __call__(cls, *args, **kwargs) -> Any:
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]
class Configuration(metaclass=Singleton):

    def __init__(self, cfgFile):
        self.cfgFile = cfgFile


    def readConf(self):
        conf = configparser.RawConfigParser()
        _path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), self.cfgFile
                )
        conf.read(_path)
        self.config = conf
        return conf

    def changeConf(self, *args):
        # print ("changeConf")
        conf = configparser.RawConfigParser()
        _path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), self.cfgFile
                )
        conf.read(_path)
        self.config = conf
        self.args = args[0]

    
        list_GettingGadgets = self.config.items('Getting Gadgets')
        list_Printing = self.config.items('Printing')
        list_Exclusion = self.config.items('Exclusion Criteria')
        # print ("list_Exclusion", list_Exclusion)
        for key, val in self.args.items():
            # print (key, val)
            for x in list_GettingGadgets:
                # print (key, x, "list_GettingGadgets")
                if(key in x):
                    # print ("\tit is there")
                    self.config['Getting Gadgets'][str(key)] = str(val)
                    # print ("\t",self.config['Getting Gadgets'][str(key)])
        for key, val in self.args.items():
            for x in list_Printing:
                if(key in x):
                    self.config['Printing'][str(key)] = str(val)
        
        for key, val in self.args.items():
            for x in list_Exclusion:
                if(key in x):
                    self.config['Exclusion Criteria'][str(key)] = str(val)
           
        #save = self.save() 
    def save(self):
        # print("saving")
        _path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), self.cfgFile
                )
        with open(_path, "w") as configfile:
            self.config.write(configfile)
            # print(configfile)
        # print("done")
