## About MapServer

https://github.com/mapserver/mapserver

>MapServer is a system for developing web-based GIS applications. The basic system consists of a CGI program that can be configured to respond to a variety of spatial requests like making maps, scalebars, and point, area and feature queries.


>MapServer was originally written by Stephen Lime. Major funding for development of MapServer has been provided by NASA through cooperative argreements with the University of Minnesota, Department of Forest Resources.
PHP/MapScript developed by DM Solutions Group.


## PHP/MapScript Vulnerabillities :bug:
As part of my PHP Internals research, I also learned about PHP **extensions**. I found a buffer overflow & format string vulnerabillities in a PHP extension called MapScript, which is part of the MapServer app. 

In this directory, you'll find two of the reports I sent privately to MapServer development team with PoCs.

All of the findings were fixed and the project maintainers allowed me to disclose those reports after I sent a responsible, full disclosure request ( thanks Steve & Jeff :D )
