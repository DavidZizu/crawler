import logging
from datamodel.search.datamodel import ProducedLink, OneUnProcessedGroup, robot_manager
from spacetime_local.IApplication import IApplication
from spacetime_local.declarations import Producer, GetterSetter, Getter
#from lxml import html,etree
import re, os
from time import time
import collections
import urllib2
from bs4 import BeautifulSoup
from datetime import datetime
from time import strptime

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
url_count = (set() 
    if not os.path.exists("successful_urls.txt") else 
    set([line.strip() for line in open("successful_urls.txt").readlines() if line.strip() != ""]))
MAX_LINKS_TO_DOWNLOAD = 10000

crawled_urls = {}                                   #dictionary to keep all the travesed urls and number of times we got a ceratin url
invalid_links = []                                  #list of invalid links received from the frontier
urls_by_subdomain = collections.defaultdict()       #dictionary to keep all the urls associated with the given subdomain
max_links = ("none", 0)                             #max number of urls retrieved from a web page
ave_time = []                                       #store time of each download to calculate the average time at the end
newest_update = ('none', datetime(1111, 11, 11, 11, 11, 11))  #store the newest file (modified based)
oldest_update = ('none', datetime(9999, 11, 11, 11, 11, 11))  #store the oldest file (modified based)

#for debug purpose: list of urls taken from the frontier and urls retrieved from this pages
debug_urls = collections.defaultdict(list)

num_url_retrieved = 0 if not os.path.exists("subdomain") else (len(open("subdomain").readlines()) - 1)                       #count number of links retrieved from web pages
num_invalid_links_from_frontier = 0 if not os.path.exists("invalid_links") else (len(open("invalid_links").readlines()) - 1)          #count number of invalid urls received from the frontier
num_urls_retrieved = 0                              #numbers of valid urls retrieved from the crawled pages

@Producer(ProducedLink)
@GetterSetter(OneUnProcessedGroup)
class CrawlerFrame(IApplication):

    def __init__(self, frame):
        self.starttime = time()
        # Set app_id <student_id1>_<student_id2>...
        self.app_id = "14056861_23302581"
        # Set user agent string to IR W17 UnderGrad <student_id1>, <student_id2> ...
        # If Graduate studetn, change the UnderGrad part to Grad.
        self.UserAgentString = "IR W17 Undergrad 14056861, 23302581"
        
        self.frame = frame
        assert(self.UserAgentString != None)
        assert(self.app_id != "")
        if len(url_count) >= MAX_LINKS_TO_DOWNLOAD:
            self.done = True

    def initialize(self):
        self.count = 0
        l = ProducedLink("http://www.ics.uci.edu", self.UserAgentString)
        print l.full_url
        self.frame.add(l)

    def update(self):
        for g in self.frame.get(OneUnProcessedGroup):
            print "Got a Group"
            outputLinks, urlResps = process_url_group(g, self.UserAgentString)
            for urlResp in urlResps:
                if urlResp.bad_url and self.UserAgentString not in set(urlResp.dataframe_obj.bad_url):
                    urlResp.dataframe_obj.bad_url += [self.UserAgentString]
            for l in outputLinks:
                if is_valid(l) and robot_manager.Allowed(l, self.UserAgentString):
                    lObj = ProducedLink(l, self.UserAgentString)
                    self.frame.add(lObj)
        if len(url_count) >= MAX_LINKS_TO_DOWNLOAD:
            self.done = True

    def shutdown(self):
        print "\n---------------------------------------------------------------\n"
        print "downloaded ", len(url_count), " in ", time() - self.starttime, " seconds."
        print "number of invalid links received from the frontier: ", num_invalid_links_from_frontier
        print "number of urls retrieved: ", num_urls_retrieved
        print "url with max number of out links: [", max_links[0], ": ", max_links[1], "]"
        print "average download time: ", sum([download_time for download_time in ave_time]) / len(ave_time), "s"
        print "newest update: ", newest_update[0], " ", newest_update[1]
        print "oldest update: ", oldest_update[0], " ", oldest_update[1]
        print "\n---------------------------------------------------------------\n"

        num_urls_by_subdomain = {}

        subdomain_file = open("subdomain", 'a')                 #open file subdomain to write all the retrieved links to a file
        for subdomain in urls_by_subdomain:
            subdomain_file.write(subdomain + ": " + "\n")
            num_urls_by_subdomain[subdomain] = 0                                  #count number of urls retrieved for each subdomain
            for url in urls_by_subdomain[subdomain]:
                num_urls_by_subdomain[subdomain] += 1
                subdomain_file.write("\t" + url + "\n")

        #number of urls retrieved from each visited subdomain
        num_urls_by_subdomain_file = open("num_urls_retrieved_from_subdomains", 'a')
        for url in num_urls_by_subdomain:
            num_urls_by_subdomain_file.write(url + ": " + str(num_urls_by_subdomain[url]) + "\n")
            print url, ": ", num_urls_by_subdomain[url]

        #store all the invalid links from the frontier
        invalid_links_file = open("invalid_links", "a")
        [invalid_links_file.write(url + "\n") for url in invalid_links]

        #store all the duplicate links and their amount
        duplicates_file = open("duplicate_urls", "a")
        [duplicates_file.write(url + ": " + str(crawled_urls[url]) + "\n") for url in crawled_urls if crawled_urls[url] > 1]

        #records other statistics
        other_stats_file = open("other_stats", "a")
        other_stats_file.write("Downloaded " + str(len(url_count)) + " in " + str(time() - self.starttime) + " seconds\n")
        other_stats_file.write("Number of invalid links received from the frontier: " + str(num_invalid_links_from_frontier) + "\n")
        other_stats_file.write("Number of URLs retrieved in total: " + str(num_urls_retrieved) + "\n")
        other_stats_file.write("URL with max number of out links: [" + str(max_links[0]) + ": " + str(max_links[1]) + "]\n")
        other_stats_file.write("Average download time per URL: " + str(sum([download_time for download_time in ave_time]) / len(ave_time)) + "seconds\n")
        other_stats_file.write("URL that was most recently modified: " + str(newest_update[0]) + " " + str(newest_update[1]) + "\n")
        other_stats_file.write("URL " + str(oldest_update[0]) + " wasn't modified since: " + str(oldest_update[1]) + "\n")

        #FOR DEBUGGING
        debug_file = open("debug_urls", "a")
        for url in debug_urls:
            debug_file.write(url + ":\n")
            for retrieved_urls in debug_urls[url]:
                debug_file.write("\t" + retrieved_urls + "\n")

        pass

def save_count(urls):
    global url_count
    urls = set(urls).difference(url_count)
    url_count.update(urls)
    if len(urls):
        with open("successful_urls.txt", "a") as surls:
            url_count.update(set(urls))
    with open("successful_urls.txt", "a") as surls:
        if urls:
            surls.write(("\n".join(urls) + "\n").encode("utf-8"))

def process_url_group(group, useragentstr):
    global ave_time
    start = time()
    rawDatas, successfull_urls = group.download(useragentstr, is_valid)
    end = time()
    if len(rawDatas) != 0:
        print "Time: ", (end - start) / len(rawDatas)
        ave_time.append((end - start) / len(rawDatas)) 
    save_count(successfull_urls)
    return extract_next_links(rawDatas), rawDatas
    
#######################################################################################
'''
STUB FUNCTIONS TO BE FILLED OUT BY THE STUDENT.
'''
def extract_next_links(rawDatas):
    global num_invalid_links_from_frontier
    global num_url_retrieved
    global crawled_urls
    global urls_by_subdomain
    global max_links
    global num_urls_retrieved
    global debug_urls
    global url_count
    global MAX_LINKS_TO_DOWNLOAD
    global newest_update
    global oldest_update

    outputLinks = list()
    '''
    rawDatas is a list of objs -> [raw_content_obj1, raw_content_obj2, ....]
    Each obj is of type UrlResponse  declared at L28-42 datamodel/search/datamodel.py
    the return of this function should be a list of urls in their absolute form
    Validation of link via is_valid function is done later (see line 42).
    It is not required to remove duplicates that have already been downloaded. 
    The frontier takes care of that.

    Suggested library: lxml
    '''

    #flamingo, ironwood

    print "\n---------------------------------------------------------------\n"

    group_num = 0
    for url_object in rawDatas:
        if group_num != 0:
            print "\n"
        print "Group ", group_num + 1
        print "URL         : ", url_object.url
        print "Error msg   : ", url_object.error_message
        print "Header      : ", url_object.headers
        print "HTTP code   : ", url_object.http_code
        print "Redirected? : ", url_object.is_redirected
        print "Final URL   : ", url_object.final_url
        group_num += 1

        #check if the url is redirected
        if url_object.is_redirected:
            url_from_frontier = url_object.final_url            #if so, get the final url (destination)
        else:
            url_from_frontier = url_object.url                  #if not, take the url given by the frontier

        #check if the given url from frontier is invalid (doesn't exist)
        if int(str(url_object.http_code)[0]) == 4:
            num_invalid_links_from_frontier += 1
            url_object.bad_url = True
            invalid_links.append(url_from_frontier)
            print '\033[91m', "INVALID URL", '\033[0m'
            continue

        #remove the last char if it is slash sign ("/")
        if url_from_frontier[-1] == '/':
            url_from_frontier = url_from_frontier[:-1]

        #check if the link from the frontier was already crawled
        if url_from_frontier not in crawled_urls:
            crawled_urls[url_from_frontier] = 1
        else:                                               #there is no point to traverse the url that we already visited
            crawled_urls[url_from_frontier] += 1
            continue

        #get the date when the URL was last modified
        if 'Last-Modified' in url_object.headers:
            split_date = url_object.headers['Last-Modified'].split(' ')         #split by " " to get each parameter imdependently
            split_time = split_date[4].split(':')                              #split time by ":" to get the time independently
            new_date = datetime(int(split_date[3]), strptime(split_date[2], '%b').tm_mon, \
                int(split_date[1]), int(split_time[0]), int(split_time[1]), int(split_time[2]))
            #set the date and time of the most recenly modified URL
            if newest_update[1] < new_date:
                newest_update = (url_from_frontier, new_date)
            #set the date and time of the oldest modification
            if oldest_update[1] > new_date:
                oldest_update = (url_from_frontier, new_date)

        #get the subdomain of the url
        url_from_frontier_parsed = urlparse(url_from_frontier)              #parse the url
        subdomain = url_from_frontier_parsed.hostname.split('.')                   #split the hostname of the link by "."
        if subdomain[0] != "www":                               
            subdomain = subdomain[0]                            #get the subdomain
        else:
            subdomain = subdomain[1]                            #get the subdomain

        if subdomain not in urls_by_subdomain:
            urls_by_subdomain[subdomain] = set()

        soup = BeautifulSoup(url_object.content, "lxml")                      #crawl the content of the downloaded web page
        num_links = 0                                           #count the number of links in this web page
        for link in soup.findAll('a'):                          #get all links
            next_link = link.get('href')                        #get all links
            new_link = urljoin(url_from_frontier, next_link)         #get the absolute form of the link
            if is_valid(new_link, False):                       #save only valid urls (increment the counter of retrieved link only if the given link is valid)
                num_urls_retrieved += 1                              #increment the counter of the retrieved links
                num_links += 1
                #remove the last char if it is slash sign ("/")
                if new_link[-1] == '/':
                    new_link = new_link[:-1]
                urls_by_subdomain[subdomain].add(new_link)
                outputLinks.append(new_link)                        #insert a link in the absolute form to the outputLinks list

                #for debugging purposes include the web page url
                debug_urls[url_from_frontier].append(new_link)

        #if the number of links retrieved from a given page is more than max number we have, then update the url and max links
        if max_links[1] < num_links:                                
            max_links = (url_from_frontier, num_links)

        '''
        #check if the url actually
        try:
            if not urllib2.urlopen(j[0]):              
                continue
        except urllib2.HTTPError, e:
            print e.code 
            continue
        except urllib2.URLError, e:
            print e.args
            continue
        '''
    print "\n---------------------------------------------------------------\n"

    #sys.stdout.write("Progress: %.2f%%   \r" %((int(len(url_count)) * 100) / MAX_LINKS_TO_DOWNLOAD) )
    sys.stdout.write("Progress: %d   \r" %len(url_count) )
    sys.stdout.flush()



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
        if frontier:
            num_invalid_links_from_frontier += 1                #increment the number of invalid links
            invalid_links.append(url)
        return False
    try:
        if ".ics.uci.edu" in parsed.hostname \
            and not re.match(".*\.(css|js|bmp|gif|jpe?g|ico" + "|png|tiff?|mid|mp2|mp3|mp4"\
            + "|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf" \
            + "|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso|epub|dll|cnf|tgz|sha1" \
            + "|thmx|mso|arff|rtf|jar|csv" \
            + "|rm|smil|wmv|swf|wma|zip|rar|gz" \
            + "|php|php.*|java.*|h5|ss|ppsx|diff|cgi|ps\.Z|jemdoc|db|lif|war|ppsx|scm)$", parsed.path.lower()) \
            and not re.match(".*(/contact/student-affairs/|/\~irus.*css|\~irus.*bart|/\~pazzani/Slides/|/\~javid/).*", parsed.path.lower()) \
            and not re.match(".*@.*", parsed.path.lower()) \
            and not re.match("^htt.*(http:/|https:/).*$", url) \
            and not re.match(".*(calendar|ganglia|archive|mlphysics|seraja).*", parsed.hostname) \
            and not re.match(".*ics.uci.edu/~develop/.*$", url) \
            and not re.match(".*ics.uci.edu/~mlearn/.*$", url) \
            and re.search("\.ics\.uci\.edu\.?$", parsed.hostname) \
            and not parsed.query:
            
            #not sure how to match identical directories using regex
            dup_dir = {}
            for direct in parsed.path.split('/'):
                if direct in dup_dir and direct != "":
                    if frontier:
                        num_invalid_links_from_frontier += 1                #increment the number of invalid links
                        invalid_links.append(url)
                    return False
                else:
                    dup_dir[direct] = 1

            return True
        else:
            if frontier:
                num_invalid_links_from_frontier += 1                #increment the number of invalid links
                invalid_links.append(url)
            return False

    except TypeError:
        print ("TypeError for ", parsed)
