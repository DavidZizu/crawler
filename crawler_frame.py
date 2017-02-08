import logging
from datamodel.search.datamodel import ProducedLink, OneUnProcessedGroup, robot_manager
from spacetime_local.IApplication import IApplication
from spacetime_local.declarations import Producer, GetterSetter, Getter
from lxml import html,etree
import re, os
from time import time

from io import StringIO
from bs4 import BeautifulSoup

import urllib2
import collections

import sys
reload(sys)
sys.setdefaultencoding('utf-8')     #to avoid ascii error

try:
    # For python 2
    from urlparse import urlparse, parse_qs, urljoin
except ImportError:
    # For python 3
    from urllib.parse import urlparse, parse_qs


logger = logging.getLogger(__name__)
LOG_HEADER = "[CRAWLER]"
url_count = 0 if not os.path.exists("successful_urls.txt") else (len(open("successful_urls.txt").readlines()) - 1)
if url_count < 0:
    url_count = 0
MAX_LINKS_TO_DOWNLOAD = 1000

#dictionary to keep all the travesed urls and number of times we got a ceratin url
crawled_urls = {}
#dictionary to keep all the urls associated with the given subdomain
urls_by_subdomain = collections.defaultdict(list)
#max number of urls retrieved from a web page
max_links = ("none", 0)

num_url_retrieved = 0 if not os.path.exists("subdomain") else (len(open("subdomain").readlines()) - 1)                       #count number of links retrieved from web pages
num_invalid_links_from_frontier = 0 if not os.path.exists("invalid_links") else (len(open("invalid_links").readlines()) - 1)          #count number of invalid urls received from the frontier                           

'''
invalid_links = open("invalid_links", 'a')
subdomain_file = open("subdomain", 'a')
stats = open("stats", 'w')
duplicate_links = open("duplicates", "w")
'''

@Producer(ProducedLink)
@GetterSetter(OneUnProcessedGroup)
class CrawlerFrame(IApplication):

    def __init__(self, frame):
        self.starttime = time()
        # Set app_id <student_id1>_<student_id2>...
        self.app_id = "14056861_54037979"
        # Set user agent string to IR W17 UnderGrad <student_id1>, <student_id2> ...
        # If Graduate studetn, change the UnderGrad part to Grad.
        self.UserAgentString = "IR W17 UnderGrad 14056861, 54037979"
		
        self.frame = frame
        assert(self.UserAgentString != None)
        assert(self.app_id != "")
        if url_count >= MAX_LINKS_TO_DOWNLOAD:
            self.done = True

    def initialize(self):
        self.count = 0
        l = ProducedLink("http://www.ics.uci.edu", self.UserAgentString)
        print l.full_url
        self.frame.add(l)

    def update(self):
        for g in self.frame.get(OneUnProcessedGroup):
            print "Got a Group"
            outputLinks = process_url_group(g, self.UserAgentString)
            for l in outputLinks:
                if is_valid(l) and robot_manager.Allowed(l, self.UserAgentString):
                    lObj = ProducedLink(l, self.UserAgentString)
                    self.frame.add(lObj)
        if url_count >= MAX_LINKS_TO_DOWNLOAD:
            self.done = True

    def shutdown(self):
        print "downloaded ", url_count, " in ", time() - self.starttime, " seconds."
        print "number of URLs retrieved: ", num_url_retrieved, \
        "; number of invalid links received from the frontier: ", num_invalid_links_from_frontier
        print "url with max number links: [", max_links[0], ": ", max_links[1], "]"

        subdomain_file = open("subdomain", 'a')                 #open file subdomain to write all the retrieved links to a file
        for subdomain in urls_by_subdomain:
            subdomain_file.write(subdomain + ": ")
            for url in urls_by_subdomain[subdomain]:
                subdomain_file.write("\t" + url)


        pass

def save_count(urls):
    global url_count
    url_count += len(urls)
    print "URLs: ", urls
    with open("successful_urls.txt", "a") as surls:
        if urls:
            surls.write("\n".join(urls) + "\n")
        #else:
        #    surls.write("\nFFFFFFFF" + "\n")

def process_url_group(group, useragentstr):
    rawDatas, successfull_urls = group.download(useragentstr, is_valid)
    save_count(successfull_urls)
    return extract_next_links(rawDatas)
    
#######################################################################################
'''
STUB FUNCTIONS TO BE FILLED OUT BY THE STUDENT.
'''
def extract_next_links(rawDatas):
    outputLinks = list()
    global num_url_retrieved
    global crawled_urls
    global urls_by_subdomain
    global max_links
    '''
    rawDatas is a list of tuples -> [(url1, raw_content1), (url2, raw_content2), ....]
    the return of this function should be a list of urls in their absolute form
    Validation of link via is_valid function is done later (see line 42).
    It is not required to remove duplicates that have already been downloaded. 
    The frontier takes care of that.

    Suggested library: lxml


    why there are blank line in successfull_urls.txt when we actually received an URL
    it seems that successfull urls contain only valid but rawDatas doesn't
    ask about the error, photo on iPhone

    '''

    print "\n---------------------------------------------------------------\n"

    for i,j in enumerate(rawDatas):
        current_link = j[0]                         #get the current link

        #check if such link (j[0]) actually exists
        #if not, go to the next one
        try:
            if not urllib2.urlopen(j[0]):               #check if the link j[0] exist
                continue
        except urllib2.HTTPError, e:
            print e.code 
            continue
        except urllib2.URLError, e:
            print e.args
            continue

        print i + 1

        if current_link not in crawled_urls:
            crawled_urls[current_link] = 1
        else:                                               #there is no point to traverse the url that we already visited
            crawled_urls[current_link] += 1
            #duplicate_links.write(current_link + "\n")
            continue

        #get the subdomain
        current_link_parsed = urlparse(current_link)            #parse the link
        subdomain = current_link_parsed.hostname.split('.')     #split the hostname of the link by "." to get the subdomain
        if subdomain[0] != "www":                               
            subdomain = subdomain[0]                            #get the subdomain
            #subdomain_file.write(subdomain[0] + " " + current_link + ":\n")          #write a subdomain to the file
        else:
            subdomain = subdomain[1]                            #get the subdomain
            #subdomain_file.write(subdomain[1] + " " + current_link + ":\n")          #write a subdomain to the file

        print current_link                                      #print the current link which is being crawled
        soup = BeautifulSoup(j[1], "lxml")                      #parse the content of the web page
        num_links = 0
        for link in soup.findAll('a'):                          #get links
            next_link = link.get('href')                        #get links
            new_link = urljoin(current_link, next_link)         #get the absolute form of the link

            #subdomain_file.write("\t" + str(new_link) + "\n")   #write the link in the absolute form to the file
            #stats.write("Retrieved: " + str(num_url_retrieved) + "\n")

            #save only valid urls (increment the counter of retrieved link only if the given link is valid)
            if is_valid(new_link, False):
                num_url_retrieved += 1                              #increment the counter of the retrieved links
                num_links += 1
                urls_by_subdomain[subdomain].append(new_link)
                outputLinks.append(new_link)                        #insert a link in the absolute form to the outputLinks list

        #if the number of links retrieved from a given page is more than max number we have, then update the url and max links
        if max_links[1] < num_links:                                
            max_links = (current_link, num_links)

    print "\n---------------------------------------------------------------\n"

    return outputLinks

def is_valid(url, frontier = True):
    global num_invalid_links_from_frontier
    '''
    Function returns True or False based on whether the url has to be downloaded or not.
    Robot rules and duplication rules are checked separately.

    This is a great place to filter out crawler traps.
    '''
    parsed = urlparse(url)
    if parsed.scheme not in set(["http", "https"]):
        #check if the function is called when we traverse a web page or when we received an url from the frontier
        if not frontier:
            num_invalid_links_from_frontier += 1                #increment the number of invalid links
            #invalid_links.write(url + "\n")                     #write an invalid link to the file
            #stats.write("Invalid: " + str(num_invalid_links_from_frontier) + "\n")
        return False
    try:
        if ".ics.uci.edu" in parsed.hostname \
            and not re.match(".*\.(css|js|bmp|gif|jpe?g|ico" + "|png|tiff?|mid|mp2|mp3|mp4"\
            + "|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf" \
            + "|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso|epub|dll|cnf|tgz|sha1" \
            + "|thmx|mso|arff|rtf|jar|csv"\
            + "|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower()) \
            and not re.match("calendar\..*$", parsed.hostname) \
            and not parsed.query:
            return True
        else:
            if not frontier:
                num_invalid_links_from_frontier += 1                #increment the number of invalid links
                #invalid_links.write(url + "\n")                 #write an invalid link to the file
                #stats.write("Invalid: " + str(num_invalid_links_from_frontier) + "\n")
            return False

    except TypeError:
        print ("TypeError for ", parsed)
