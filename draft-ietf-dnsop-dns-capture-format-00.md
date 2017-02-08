%%%
    Title = "C-DNS: A DNS Packet Capture Format"
    abbrev = "C-DNS: A DNS Packet Capture Format"
    category = "std"
    docName= "draft-ietf-dnsop-dns-capture-format-00"
    ipr = "trust200902"
    area = "Operations Area"
    workgroup = "dnsop"
    keyword = ["DNS"]
    date = 2016-12-06T00:00:00Z
    [pi]
    toc = "yes"
    compact = "yes"
    symrefs = "yes"
    sortrefs = "yes"
    subcompact = "no"
    [[author]]
    initials="J."
    surname="Dickinson"
    fullname="John Dickinson"
    organization = "Sinodun IT"
      [author.address]
      email = "jad@sinodun.com"
      [author.address.postal]
      streets = ["Magdalen Centre", "Oxford Science Park"]
      city = "Oxford"
      code = "OX4 4GA"
    [[author]]
    initials="J."
    surname="Hague"
    fullname="Jim Hague"
    organization = "Sinodun IT"
      [author.address]
      email = "jim@sinodun.com"
      [author.address.postal]
      streets = ["Magdalen Centre", "Oxford Science Park"]
      city = "Oxford"
      code = "OX4 4GA"
    [[author]]
    initials="S."
    surname="Dickinson"
    fullname="Sara Dickinson"
    organization = "Sinodun IT"
      [author.address]
      email = "sara@sinodun.com"
      [author.address.postal]
      streets = ["Magdalen Centre", "Oxford Science Park"]
      city = "Oxford"
      code = "OX4 4GA"
    [[author]]
    initials="T."
    surname="Manderson"
    fullname="Terry Manderson"
    organization = "ICANN"
      [author.address]
      email = "terry.manderson@icann.org"
      [author.address.postal]
      streets = ["12025 Waterfront Drive", " Suite 300"]
      city = "Los Angeles"
      code = "CA 90094-2536"
    [[author]]
    initials="J."
    surname="Bond"
    fullname="John Bond"
    organization = "ICANN"
      [author.address]
      email = "john.bond@icann.org"
      [author.address.postal]
      streets = ["12025 Waterfront Drive", " Suite 300"]
      city = "Los Angeles"
      code = "CA 90094-2536"
%%%

.# Abstract
This document describes a data representation for collections of 
DNS messages.
The format is designed for efficient storage and transmission of large packet captures of DNS traffic;
it attempts to minimize the size of such packet capture files but retain the 
full DNS message contents along with the most useful transport metadata. 
It is intended to assist with 
the development of DNS traffic monitoring applications.

{mainmatter}

# Introduction

There has long been a need to collect DNS queries and responses
on authoritative and recursive name servers for monitoring and analysis.
This data is used in a number of ways including traffic monitoring, 
analyzing network attacks and "day in the life" (DITL) [@ditl] analysis.

A wide variety of tools already exist that facilitate the collection of
DNS traffic data, such as DSC [@dsc], packetq [@packetq], dnscap [@dnscap] and dnstap [@dnstap].
However, there is no standard exchange format for large DNS packet captures.
The PCAP [@pcap] or PCAP-NG [@pcapng] formats are typically used in practice for packet captures, but these file
formats can contain a great deal of additional information that is not directly pertinent to DNS traffic analysis
and thus unnecessarily increases the capture file size.

There has also been work on using text based formats to describe 
DNS packets such as [@?I-D.daley-dnsxml#00], [@?I-D.hoffman-dns-in-json#09], but these are largely 
aimed at producing convenient representations of single messages.

Many DNS operators may receive hundreds of thousands of queries per second on a single
name server instance so
a mechanism to minimize the storage size (and therefore upload overhead) of the
data collected is highly desirable.

The format described in this document, C-DNS (Compacted-DNS), focusses on the problem of capturing and storing large packet capture
files of DNS traffic. with the following goals in mind:

* Minimize the file size for storage and transmission
* Minimizing the overhead of producing the packet capture file and the cost of any further (general purpose) compression of the file

This document contains:

* A discussion of the some common use cases in which such DNS data is collected (#data-collection-use-cases)
* A discussion of the major design considerations in developing an efficient
  data representation for collections of DNS messages (#design-considerations)
* A conceptual overview of the C-DNS format (#conceptual-overview)
* A description of why CBOR [@!RFC7049] was chosen for this format (#choice-of-cbor)
* The definition of the C-DNS format for the collection of DNS messages (#the-cdns-format).
* Notes on converting C-DNS data to PCAP format (#cdns-to-pcap)
* Some high level implementation considerations for applications designed to
  produce C-DNS (#data-collection)

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [@!RFC2119].

The parts of DNS messages are named as they are in [@!RFC1035]. In specific,
the DNS message has five sections: Header, Question, Answer, Authority,
and Additional.

Pairs of DNS messages are called a Query and a Response.

# Data Collection Use Cases

In an ideal world, it would be optimal to collect full packet captures of all
packets going in or out of a name server. However, there are several
design choices or other limitations that are common to many DNS installations and operators.

* DNS ervers are hosted in a variety of situations
    * Self-hosted servers
    * Third party hosting (including multiple third parties)
    * Third party hardware (including multiple third parties)
* Data is collected under different conditions
    * On well-provisioned servers running in a steady state
    * On heavily loaded servers
    * On virtualized servers
    * On servers that are under DoS attack
    * On servers that are unwitting intermediaries in DoS attacks
* Traffic can be collected via a variety of mechanisms
    * On the same hardware as the name server itself 
    * Using a network tap on an adjacent host to listen to DNS traffic
    * Using port mirroring to listen from another host
* The capabilities of data collection (and upload) networks vary
    * Out-of-band networks with the same capacity as the in-band network
    * Out-of-band networks with less capacity than the in-band network
    * Everything being on the in-band network

Thus, there is a wide range of use cases from very limited data collection
environments (third party hardware, servers that are under attack, packet capture
on the name server itself and no out-of-band network) to "limitless"
environments (self hosted, well provisioned servers, using a network tap or port
mirroring with an out-of-band networks with the same capacity as the in-band network).
In the former, it is infeasible to reliably collect full packet captures, especially if the server
is under attack. In the latter case, collection of full packet captures may be reasonable.

As a result of these restrictions, the C-DNS data format was designed
with the most limited use case in mind such that:

* data collection will occur on the same hardware as the name server itself
* collected data will be stored on the same hardware as the name server itself, at least temporarily
* collected data being returned to some central analysis system will use the same network interface as the DNS queries and responses
* there can be multiple third party servers involved

Because of these considerations, a major factor in the design of the
format is minimal storage size of the capture files.

Another significant consideration for any application that records DNS traffic 
is that the running of the name server software and the transmission of
DNS queries and responses are the most important jobs of a name server; capturing data is not.
Any data collection system co-located with the name server needs to be intelligent enough to
carefully manage its CPU, disk, memory and network 
utilization. This leads to designing a format that requires a relatively low
overhead to produce and minimizes the requirement for further potentially costly
compression.

However, it was also essential that interoperability with less restricted
infrastructure was maintained. In particular, it is highly desirable that the
collection format should facilitate the re-creation of common formats (such as PCAP) that are as 
close to the original as is realistic given the restrictions above.


# Design Considerations

This section presents some of the major design considerations used in the development of the C-DNS format.

<!--SD: Want to re-format this section as a list but complex lists seem broken -->

* The basic unit of data is a combined DNS Query and the associated Response (a "Q/R data item"). The same structure
will be used for unmatched Queries and Responses. Queries without Responses will be 
captured omitting the response data. Responses without queries will be captured omitting the Query data (but using
the Question section from the response, if present, as an identifying QNAME).

Rationale: A Query and Response represents the basic level of a clients interaction with the server. 
Also, combining the Query and Response into one item often reduces storage requirements due to commonality in the data
of the two messages.

* Each Q/R data item will comprise a default Q/R data description and a set of optional sections.
Inclusion of optional sections shall be configurable.
 
Rationale: Different users will have different requirements for data to be available for analysis. 
Users with minimal requirements should not have to pay the cost of recording full data, however this will
limit the ability to reconstruct packet captures. For example, omitting the resource records from a Response will
reduce the files size, and in principle responses can be synthesized if there is enough context.

* Multiple Q/R data items will be collected into blocks in the format. Common data in a block will be abstracted and 
referenced from individual Q/R data items by indexing. The maximum number of Q/R data items in a block will be configurable.
 
Rationale: This blocking and indexing provides a significant reduction in the volume of file data generated.
Although this introduces complexity, it provides compression of the data that makes use of knowledge of the DNS packet structure.

[TODO: Further discussion on commonality between DNS packets e.g.

* common query signatures
* for the authoritative case, there are a finite set of valid responses and much commonality in NXDOMAIN responses]
	
It is anticipated 
that the files produced can be subject to further compression using general purpose compression tools. Measurements show that 
blocking significantly reduces the CPU required to perform such strong compression. See (#simple-versus-block-coding).

* Metadata about other packets received should also be included in each block. For example, counts of malformed DNS packets and non-DNS packets
(e.g. ICMP, TCP resets) sent to the server may of interest.
 
It should be noted that any structured capture format that does not capture the DNS payload byte for byte will likely be limited to some extent in
that it cannot represent "malformed" DNS packets. Only those packets that can be transformed reasonably into the structured format
can be represented by it. So if a query is malformed this will lead to the (well formed) DNS responses with error code FORMERR appearing as "unmatched".

* Data on malformed packets will optionally be recorded. There are three distinct types of packets that are considered "malformed":

    * Packets that cannot be decoded into a well-formed IP or IPv6 packet, or where a valid DNS header cannot be extracted.
      A valid DNS header is one where the identifier, flags and codes, and question count words are present and well-formed, and
      unless the question count is 0 a single question is present in the question section.
    * Packets with a well-formed DNS header, but well-formed records corresponding to the full count of records specified in each section
      are not present.
    * Packets with well-formed DNS content, but with additional data following the DNS content.

Rationale: Many name servers will process queries on a best-effort basis in accordance with Postel's Law, and do not insist on
completely well-formed packets. Name servers will also generally ignore any trailing data following well-formed DNS content. Users may wish
to be informed of such transactions, or input data that cannot be decoded to even a DNS header and which therefore cannot be meaningfully
processed as part of the Q/R data item stream, and may wish to be able to analyse these malformed inputs as, for example, possible attack
vectors. Therefore these interactions with the name server should be recorded where possible, but flagged as malformed.

QUESTION: Should a valid DNS header include additional conditions?

* The flags and codes words has valid values for operation code and response code.
* A query has response code 0.
* All zero bits are set to 0.

# Conceptual Overview

The following figures show purely schematic representations of the C-DNS format to convey the high-level
structure of the C-DNS format. (#the-cdns-format) provides a detailed discussion of the CBOR representation
and individual elements.

![Figure showing the C-DNS format (PNG)](https://github.com/dns-stats/draft-dns-capture-format/blob/master/cdns_format.png)

![Figure showing the C-DNS format (SVG)](https://github.com/dns-stats/draft-dns-capture-format/blob/master/cdns_format.svg)

![Figure showing the Q/R data item and Block tables format (PNG)](https://github.com/dns-stats/draft-dns-capture-format/blob/master/qr_data_format.png)

![Figure showing the Q/R data item and Block tables format (SVG)](https://github.com/dns-stats/draft-dns-capture-format/blob/master/qr_data_format.svg)

# Choice of CBOR

This document presents a detailed format description using CBOR, the Concise Binary Object Representation defined in [@!RFC7049].

The choice of CBOR was made taking a number of factors into account.
 
* CBOR is a binary representation, and thus is economical in storage space. 
* Other binary representations were investigated, and whilst all had attractive features,
none had a significant advantage over CBOR. See (#comparison-of-binary-formats) for some discussion of this.
* CBOR is an IETF standard and familiar to IETF participants. It is based on the now-common 
ideas of lists and objects, and thus requires very little familiarization for those in the wider industry.
* CBOR is a simple format, and can easily be implemented from scratch if necessary. More complex formats
require library support which may present problems on unusual platforms.
* CBOR can also be easily converted to text formats such as JSON ([@RFC7159]) for debugging and other human inspection requirements.
* CBOR data schemas can be described using CDDL [@?I-D.greevenbosch-appsawg-cbor-cddl#09]. 

# The C-DNS format

## CDDL definition

The CDDL definition for the C-DNS format is given in (#cddl).

## Format overview

A C-DNS file begins with a file header containing a file type identifier and
a preamble. The preamble contains information on the collection settings.

The file header is followed by a series of data blocks.

A block consists of a block header, containing various tables of common data,
and some statistics for the traffic received over the block. The block header
is then followed by a list of the Q/R date items detailing the queries and responses
received during the block. The list of Q/R data items is in turn followed by a list
of per-client counts of particular IP events that occurred during collection of
the block data.

The exact nature of the DNS data will affect what block size is the best fit, 
however sample data for a root server indicated that block sizes or up to
10,000 Q/R data items give good results. See (#block-size-choice) for more details.

If no field type is specified, then the field is unsigned.

In all quantities that contain bit flags, bit 0 indicates the least significant bit.
An item described as an index is the index of the Q/R data item in the referenced table.
Indexes are 1-based. An index value of 0 is reserved to mean "not present".

<!-- ######################################## NOTE TO AUTHORS

Yipes! The fields in these tables are not the actual field names. In fact, they don't even
have the same capitalization. I would suggest either calling each first column "Contents
of field" or, better, just use the actual field names for the Field column.

Editorial: Many descriptions end in a period even though they are not at all sentences.
All those periods should be removed.

"Optional" is listed only for *some* of the optional fields. I propose that you
(a) make it correct everywhere and (b) shorten it to be a ? before the Field name.


############################################# -->

## File header contents

The file header contains the following:

Field | Type | Description
:----|:----|:-----
File type ID | Text string | String "C-DNS" identifying the file type
||
File preamble | Map of items | Collection information for the whole file.
||
File Blocks | Array of Blocks | The data blocks

## File preamble contents

The file preamble contains the following:

Field | Type | Description
:----|:----|:-----
major-format-version | Unsigned | Unsigned integer '0'. The major version of format used in file.
||
minor-format-version | Unsigned | Unsigned integer '1'. The minor version of format used in file.
||
private-version | Unsigned | Version indicator available for private use by applications. Optional.
||
Configuration | Map of items | The collection configuration. Optional.
||
Generator ID | Text string | String identifying the collection program. Optional.
||
Host ID | Text string | String identifying the collecting host. Blank if converting an existing packet capture file. Optional.

## Configuration contents

The collection configuration contains the following items. All are optional.

Field | Type | Description
:----|:----|:-----
Query timeout | Unsigned | To be matched with a query, a response must arrive within this number of seconds.
||
Skew timeout | Unsigned | The network stack may report a response before the corresponding query. A response is not considered to be missing a query until after this many micro-seconds.
||
Snap length | Unsigned | Collect up to this many bytes per packet.
||
Promiscuous mode | Unsigned | 1 if promiscuous mode was enabled on the interface, 0 otherwise.
||
Interfaces | Array of text strings | Identifiers of the interfaces used for collection.
||
VLAN IDs | Array of unsigned | Identifiers of VLANs selected for collection.
||
Filter | Text string | `tcpdump` [@pcap] style filter for input.
||
Query collection options | Unsigned | Bit flags indicating sections in Query packets to be collected.
 | | Bit 0. Collect second and subsequent question sections.
 | | Bit 1. Collect Answer sections.
 | | Bit 2. Collect Authority sections.
 | | Bit 3. Collection Additional sections.
||
Response collection options | Unsigned | Bit flags indicating sections in Response packets to be collected.
 | | Bit 0. Collect second and subsequent question sections.
 | | Bit 1. Collect Answer sections.
 | | Bit 2. Collect Authority sections.
 | | Bit 3. Collection Additional sections.
||
Accept RR types | Array of text strings | A set of RR type names [@rrtypes]. If not empty, only the nominated RR types are collected.
||
Ignore RR types | Array of text strings | A set of RR type names [@rrtypes]. If not empty, all RR types are collected except those listed. If present, this item must be empty if a non-empty list of Accept RR types is present.

## Block contents

Each block contains the following:

Field | Type | Description
:----|:----|:-----
Block preamble | Map of items | Overall information for the block.
||
Block statistics | Map of statistics | Statistics about the block.
||
Block tables | Map of tables | The tables containing data referenced by individual Q/R data items.
||
Q/Rs | Array of Q/R data items | Details of individual Q/R data items.
||
Address Event Counts | Array of Address Event counts | Per client counts of ICMP messages and TCP resets.
||
Malformed Packets | Array of malformed packets | Wire contents of malformed packets. 

## Block preamble map

The block preamble map contains overall information for the block.

Field | Type | Description
:-----|:-----|:-----------
Timestamp | Array of unsigned | A timestamp for the earliest record in the block. The timestamp is specified as a CBOR array with two or three elements. The first two elements are as in Posix struct timeval. The first element is an unsigned integer time_t and the second is an unsigned integer number of microseconds. The third, if present, is an unsigned integer number of picoseconds. The microsecond and picosecond items always have a value between 0 and 999,999.

## Block statistics

The block statistics section contains some basic statistical information about the block.

Field | Type | Description
:-----|:-----|:-----------
Total packets | Unsigned | Total number of packets processed during the block.
Total pairs | Unsigned | Total number of query/response pairs in the block.
Unmatched queries | Unsigned | Number of unmatched queries in the block.
Unmatched responses | Unsigned | Number of unmatched responses in the block.
Malformed packets | Unsigned | Number of malformed packets found in input for the block.
Non-DNS packets | Unsigned | Number of non-DNS packets found in input for the block.
Out-of-order packets | Unsigned | Number of packets processed during input for the block that were not in strict chronological order.
Dropped pairs | Unsigned | Count of query/responses not written due to overflow.
Dropped packets | Unsigned | Count of raw packets not written due to overflow.
Dropped non-DNS packets | Unsigned | Count of ignored packets not written due to overflow.

QUESTION: The last 3 are info about compactor performance.Should they be in the standard?

## Block table map

The block table map contains the block tables. Each element, or table, is an array. The following tables detail the contents of each block table.

The Present column in the following tables indicates the circumstances when an optional field will be present. A Q/R data item may be:

* A Query plus a Response.
* A Query without a Response.
* A Response without a Query.

Also:

* A Query and/or a Response may contain an OPT section.
* A Question may or may not be present. If the Query is available, the Question section of the Query is used. If no Query is available, the Question section of the Response is used. Unless otherwise noted, a Question refers to the first Question in the Question section.

So, for example, a field listed with a Present value of QUERY is present whenever the Q/R data item contains a Query. If the pair contains a Response only, the field will not be present.

## IP address table
This table holds all client and server IP addresses in the block. Each item in the table is a single IP address.

Field | Type | Description
:-----|:-----|:-----------
Address | Byte string | The IP address, in network byte order. The string is 4 bytes long for an IPv4 address, 16 bytes long for an IPv6 address.

## Class/Type table

This table holds pairs of RR CLASS and TYPE values. Each item in the table is a CBOR map.

Field | Description
:-----|:-----------
Class | CLASS value.
||
Type | TYPE value.

[TODO: Can this be optimized? Should a class of IN be inferred if not present?]

## Name/RDATA table

This table holds the contents of all NAME or RDATA items in the block. Each item in the table is the content of a single NAME or RDATA.

Field | Type | Description
:-----|:-----|:-----------
Data | Byte string | The NAME or RDATA contents. NAMEs, and labels within RDATA contents, are in uncompressed label format.

## Query Signature table

This table holds elements of the Q/R data item that are often common to between different individual Q/R data items. Each item in the table is a CBOR map. Each item in the map has an unsigned value and an unsigned key.

The following abbreviations are used in the Present (P) column 

* Q = QUERY
* A = Always
* QT = QUESTION
* QO = QUERY, OPT
* QR = QUERY & RESPONSE
* R = RESPONSE

Field | P | Description
:-----|:--------|:-----------
Server address | A | The index in the IP address table of the server IP address.
||
Server port | A | The server port.
||
Transport flags | A | Bit flags describing the protocol used to service the query. Bit 0 is the least significant bit.
 | | Bit 0. Transport type. 0 = UDP, 1 = TCP.
 | | Bit 1. IP type. 0 = IPv4, 1 = IPv6.
||
Q/R signature flags | A | Bit flags indicating information present in this Q/R data item. Bit 0 is the least significant bit.
 | | Bit 0. 1 if a Query is present.
 | | Bit 1. 1 if a Response is present.
 | | Bit 2. 1 if one or more Question is present.
 | | Bit 3. 1 if a Query is present and it has an OPT Resource Record.
 | | Bit 4. 1 if a Response is present and it has an OPT Resource Record.
 | | Bit 5. 1 if a Response is present but has no Question.
 | | Bit 6. 1 if a Query is present but malformed.
 | | Bit 7. 1 if a Response is present but malformed.
||
Query OPCODE | Q | Query OPCODE.
||
Q/R DNS flags | A | Bit flags with values from the Query and Response DNS flags. Bit 0 is the least significant bit. Flag values are 0 if the Query or Response is not present.
 | | Bit 0. Query Checking Disabled (CD).
 | | Bit 1. Query Authenticated Data (AD).
 | | Bit 2. Query reserved (Z).
 | | Bit 3. Query Recursion Available (RA).
 | | Bit 4. Query Recursion Desired (RD).
 | | Bit 5. Query TrunCation (TC).
 | | Bit 6. Query Authoritative Answer (AA).
 | | Bit 7. Query DNSSEC answer OK (D0).
 | | Bit 8. Response Checking Disabled (CD).
 | | Bit 9. Response Authenticated Data (AD).
 | | Bit 10. Response reserved (Z).
 | | Bit 11. Response Recursion Available (RA).
 | | Bit 12. Response Recursion Desired (RD).
 | | Bit 13. Response TrunCation (TC).
 | | Bit 14. Response Authoritative Answer (AA).
||
Query RCODE | Q | Query RCODE. If the Query contains OPT, this value incorporates any EXTENDED_RCODE_VALUE.
||
Question Class/Type | QT | The index in the Class/Type table of the CLASS and TYPE of the first Question.
||
Question QDCOUNT | QT | The QDCOUNT in the Query, or Response if no Query present.
||
Query ANCOUNT | Q | Query ANCOUNT.
||
Query ARCOUNT | Q | Query ARCOUNT.
||
Query NSCOUNT | Q | Query NSCOUNT.
||
Query EDNS version | QO | The Query EDNS version.
||
EDNS UDP size | QO | The Query EDNS sender's UDO payload size
||
Query OPT RDATA | QO | The index in the NAME/RDATA table of the OPT RDATA.
||
Response RCODE | R | Response RCODE. If the Response contains OPT, this value incorporates any EXTENDED_RCODE_VALUE.

## Question table

This table holds details on individual Questions in a Question section. Each item in the table is a CBOR map containing a single Question. Each item in the map has an unsigned value and an unsigned key. This data is optionally collected.

Field | Description
:-----|:-----------
QNAME | The index in the NAME/RDATA table of the QNAME.
||
Class/Type | The index in the Class/Type table of the CLASS and TYPE of the Question.

## Resource Record (RR) table

This table holds details on individual Resource Records in RR sections. Each item in the table is a CBOR map containing a single Resource Record. This data is optionally collected.

Field | Description
:-----|:-----------
NAME | The index in the NAME/RDATA table of the NAME.
||
Class/Type | The index in the Class/Type table of the CLASS and TYPE of the RR.
||
TTL | The RR Time to Live.
||
RDATA | The index in the NAME/RDATA table of the RR RDATA.

## Question list table

This table holds a list of second and subsequent individual Questions in a Question section. Each item in the table is a CBOR unsigned integer. This data is optionally collected.

Field | Description
:-----|:-----------
Question | The index in the Question table of the individual Question.

## Resource Record list table

This table holds a list of individual Resource Records in a Answer, Authority or Additional section. Each item in the table is a CBOR unsigned integer. This data is optionally collected.

Field | Description
:-----|:-----------
RR | The index in the Resource Record table of the individual Resource Record.

## Query/Response data

The block Q/R data is a CBOR array of individual Q/R data items. Each item in the array is a CBOR map containing details on the individual Q/R data item. 

Note that there is no requirement that the elements of the Q/R array are presented in strict chronological order.

The following abbreviations are used in the Present (P) column 

* Q = QUERY
* A = Always
* QT = QUESTION
* QO = QUERY, OPT
* QR = QUERY & RESPONSE
* R = RESPONSE

Each item in the map has an unsigned value (with the exception of those listed below) and an unsigned key.

* Query extended information and Response extended information which are of Type Extended Information.
* Response delay which is an integer (This can be negative if the network stack/capture library returns them out of order.)

Field | P | Description
:-----|:--------|:-----------
Time offset | A | Q/R timestamp as an offset in microseconds and optionally picoseconds from the Block preamble Timestamp. The timestamp is the timestamp of the Query, or the Response if there is no Query.
||
Client address | A | The index in the IP address table of the client IP address.
||
Client port | A | The client port.
||
Transaction ID | A | DNS transaction identifier.
||
Query signature | A | The index of the more information on the Q/R in the Query Signature table.
||
Client hoplimit | Q | The IPv4 TTL or IPv6 Hoplimit from the Query packet.
||
Response delay | QR | The time different between Query and Response, in microseconds.
||
Question NAME | QT | The index in the NAME/RDATA table of the QNAME for the first Question.
||
Response size | R | The size of the DNS message (not the packet containing the message, just the DNS message) that forms the Response.
||
Query extended information | Q | Extended Query information. This item is only present if collection of extra Query information is configured.
||
Response extended information | R | Extended Response information. This item is only present if collection of extra Query information is configured.

The collector always collects basic Q/R information. It may be configured to collect details on Question, Answer, Authority and Additional sections of the Query, the Response or both. Note that only the second and subsequent Questions of any Question section are collected (the details of the first are in the basic information), and that OPT Records are not collected in the Additional section.

The Extended information is a CBOR map as follows. Each item in the map is present only of collection of the relevant details is configured. Each item in the map has an unsigned value and an unsigned key.

Field | Description
:-----|:-----------
Question | The index in the Questions list table of the entry listing the second and subsequent Question sections for the Query or Response.
||
Answer | The index in the RR list table of the entry listing the Answer Resource Record sections for the Query or Response.
||
Authority | The index in the RR list table of the entry listing the Authority Resource Record sections for the Query or Response.
||
Additional | The index in the RR list table of the entry listing the Additional Resource Record sections for the Query or Response.

## Address Event counts

This table holds counts of various IP related events relating to traffic
with individual client addresses.

Field | Type | Description
:-----|:-----|:-----------
Event type | Unsigned | The type of event. The following events types are currently defined:
 | | 0. TCP reset.
 | | 1. ICMP time exceeded.
 | | 2. ICMP destination unreachable.
 | | 3. ICMPv6 time exceeded.
 | | 4. ICMPv6 destination unreachable.
 | | 5. ICMPv6 packet too big.
||
Event code | Unsigned | A code relating to the event. Optional.
||
Address index | Unsigned | The index in the IP address table of the client address.
||
Count | Unsigned | The number of occurrences of this event during the block collection period.

## Malformed packet records

This optional table records the content of malformed packets.

Field | Type | Description
:-----|:-----|:-----------
Time offset | A | Packet timestamp as an offset in microseconds and optionally picoseconds from the Block preamble Timestamp.
||
Malformed type | Unsigned | The type of malformation. The following types are currently defined:
 | | 0. Cannot decode IP or extract valid DNS header.
 | | 1. DNS header is valid, but other DNS content is malformed.
 | | 2. DNS content is well-formed but the packet contains trailing data.
||
Contents | Byte string | The packet content in wire format.

# C-DNS to PCAP

It is possible to re-construct PCAP files from the C-DNS format in a lossy fashion.
Some of the issues with reconstructing both the DNS payload and the 
full packet stream are outlined here.

The reconstruction depends on whether or not all the optional sections
of both the query and response were captured in the C-DNS file. 
Clearly, if they were not all captured, the reconstruction will be imperfect.

Even if all sections of the response were captured, one cannot reconstruct the DNS
response payload exactly due to the fact that some DNS names in the message on the wire
may have been compressed.
(#name-compression) discusses this is more detail.

Some transport
information is not captured in the C-DNS format. For example, the following aspects
of the original packet stream cannot be re-constructed from the C-DNS format:

* IP fragmentation
* TCP stream information: 
     * Multiple DNS messages may have been sent in a single TCP segment
     * A DNS payload may have be split across multiple TCP segments
     * Multiple DNS messages may have be sent on a single TCP session
* Malformed DNS messages if they are not recorded
* Non-DNS packets

Simple assumptions can be made on the reconstruction: fragmented and DNS-over-TCP messages
can be reconstructed into single packets and a single TCP session can be constructed
for each TCP packet.

Additionally, if malformed packets are captured in the C-DNS or separate packet captures,
and non-DNS packets are captured separately into packet captures,
they can be merged with packet captures reconstructed from C-DNS to produce a more complete
packet stream.

## Name Compression

All the names stored in the C-DNS format are full domain names; no DNS style name compression is used
on the individual names within the format. Therefore when reconstructing a packet,
name compression must be used in order to reproduce the on the wire representation of the
packet.

[@!RFC1035] name compression works by substituting trailing sections of a name with a
reference back to the occurrence of those sections earlier in the packet.
Not all name server software uses the same algorithm when compressing domain names 
within the responses. Some attempt maximum recompression
at the expense of runtime resources, others use heuristics to balance compression
and speed and others use different rules for what is a valid compression target. 

This means that responses to the
same question from different name server software which match in terms of DNS payload 
content (header, counts, RRs with name compression removed) do
not necessarily match byte-for-byte on the wire. 

Therefore, it is not possible to ensure that the DNS response payload is reconstructed
byte-for-byte from C-DNS data. However, it can at least, in principle, be reconstructed to have the correct payload
length (since the original response length is captured) if there is enough knowledge of the
commonly implemented name compression algorithms. For example, a simplistic approach would be
to try each algorithm in turn
to see if it reproduces the original length, stopping at the first match. This would not 
guarantee the correct algorithm has been used as it is possible to match the length
whilst still not matching the on the wire bytes but, without further information added to the C-DNS data, this is the
best that can be achieved.

(#dns-name-compression-example) presents an example of two different compression
algorithms used by well-known name server software.

# Data Collection

This section describes a non-normative proposed algorithm for the processing of a captured stream of DNS queries and
responses and matching queries/responses where possible.

For the purposes of this discussion, it is assumed that the input has been pre-processed such that:

1. All IP fragmentation reassembly, TCP stream reassembly, and so on, has already been performed
1. Each message is associated with transport metadata required to generate the Primary ID (see below)
1. Each message has a well-formed DNS header of 12 bytes and (if present) the first RR in the Question section can be parsed to generate the Secondary ID (see below). As noted earlier, this requirement can result in a malformed query being removed in the pre-processing stage, but the correctly formed response with RCODE of FORMERR being present.

DNS messages are processed in the order they are delivered to the application.
It should be noted that packet capture libraries do not necessary provide packets in strict chronological order.

[TODO: Discuss the corner cases resulting from this in more detail.]

## Matching algorithm

A schematic representation of the algorithm for matching Q/R data items is shown in the following diagram:

![Figure showing the packet matching algorithm format (PNG)](https://github.com/dns-stats/draft-dns-capture-format/blob/master/packet_matching.png)

![Figure showing the packet matching algorithm format (SVG)](https://github.com/dns-stats/draft-dns-capture-format/blob/master/packet_matching.svg)

Further details of the algorithm are given in the following sections.

## Message identifiers

### Primary ID (required)

A Primary ID can be constructed for each message which is composed of the following data:

1. Source IP Address
1. Destination IP Address
1. Source Port
1. Destination Port
1. Transport
1. DNS Message ID

### Secondary ID (optional)

If present, the first question in the Question section is used as a secondary ID
for each message. Note that there may be well formed DNS queries that have a
QDCOUNT of 0, and some responses may have a QDCOUNT of 0
(for example, RCODE=FORMERR or NOTIMP)

## Algorithm Parameters

1. Configurable timeout

## Algorithm Requirements

The algorithm is designed to handle the following input data:

1. Multiple queries with the same Primary ID (but different Secondary ID) arriving before any responses for these queries are seen.
1. Multiple queries with the same Primary and Secondary ID arriving before any responses for these queries are seen.
1. Queries for which no later response can be found within the specified timeout.  
1. Responses for which no previous query can be found within the specified timeout. 

## Algorithm Limitations

For cases 1 and 2 listed in the above requirements, it is not possible to unambiguously match queries with responses.
This algorithm chooses to match to the earliest query with the correct Primary and Secondary ID.

## Workspace

A FIFO structure is used to hold the Q/R data items during processing.

## Output

The output is a list of Q/R data items. Both the Query and Response elements are optional in these items,
therefore Q/R data items have one of three types of content:

1. A matched pair of query and response messages
1. A query message with no response
1. A response message with no query

The timestamp of a list item is that of the query for cases 1 and 2 and that of the response for case 3.

## Post Processing

When ending capture, all remaining entries in the Q/R data item FIFO should be treated as timed out queries.

# IANA Considerations

None

# Security Considerations

Any control interface MUST perform authentication and encryption.

Any data upload MUST be authenticated and encrypted.

# Acknowledgements

The authors wish to thank CZ.NIC, in particular Tomas Gavenciak, for many useful discussions on binary 
formats, compression and packet matching. Also Jan Vcelak and Wouter Wijngaards for discussions on
name compression.

Thanks to Robert Edmonds, Paul Hoffman and Jerry Lundström for review.

Also, Miek Gieben for [mmark](https://github.com/miekg/mmark)

# Changelog
draft-ietf-dnsop-dns-capture-format-00

* Changed dnstap.io to dnstap.info
* qr_data_format.png was cut off at the bottom
* Update authors address
* Improve wording in Abstract
* Changed DNS-STAT to C-DNS in CDDL
* Set the format version in the CDDL
* Added a TODO: Add block statistics
* Added a TODO: Add extend to support pico/nano. Also do this for Time offset and Response delay
* Added a TODO: Need to develop optional representation of malformed packets within C-DNS and what this means for packet matching.  This may influence which fields are optional in the rest of the representation.
* Added section on design goals to Introduction
* Added a TODO: Can Class be optimised?  Should a class of IN be inferred if not present?

draft-dickinson-dnsop-dns-capture-format-00

* Initial commit

<reference anchor='dsc' target='https://www.dns-oarc.net/tools/dsc'>
    <front>
        <title>DSC</title>
        <author initials='D.' surname='Wessels' fullname='Duane Wessels'>
            <organization>Verisign</organization>
        </author>
        <author initials='J.' surname='Lundstrom' fullname='Jerry Lundstrom'>
            <organization>DNS-OARC</organization>
        </author>
        <date year='2016'/>
    </front>
</reference>

<reference anchor='packetq' target='https://github.com/dotse/PacketQ'>
    <front>
        <title>PacketQ</title>
        <author>
            <organization>.SE - The Internet Infrastructure Foundation</organization>
        </author>
        <date year='2014'/>
    </front>
</reference>

<reference anchor='dnscap' target='https://www.dns-oarc.net/tools/dnscap'>
    <front>
        <title>DNSCAP</title>
        <author>
            <organization>DNS-OARC</organization>
        </author>
        <date year='2016'/>
    </front>
</reference>

<reference anchor='dnstap' target='http://dnstap.info/'>
    <front>
        <title>dnstap</title>
        <author>
            <organization>dnstap.info</organization>
        </author>
        <date year='2016'/>
    </front>
</reference>

<reference anchor='ditl' target='https://www.dns-oarc.net/oarc/data/ditl'>
    <front>
        <title>DITL</title>
        <author>
            <organization>DNS-OARC</organization>
        </author>
        <date year='2016'/>
    </front>
</reference>

<reference anchor='pcapng' target='https://github.com/pcapng/pcapng'>
    <front>
        <title>pcap-ng</title>
        <author initials='M.' surname='Tuexen' fullname='Michael Tuexen'>
            <organization>Muenster Univ. of Appl. Sciences</organization>
            <address>
                <email>tuexen@fh-muenster.de</email>
            </address>
        </author>
        <author initials='F.' surname='Risso' fullname='Fulvio Risso'>
            <organization>Politecnico di Torino</organization>
            <address>
                <email>fulvio.risso@polito.it</email>
            </address>
        </author>
        <author initials='J.' surname='Bongertz' fullname='Jasper Bongertz'>
            <organization>Airbus DS CyberSecurity</organization>
            <address>
                <email>jasper@packet-foo.com</email>
            </address>
        </author>
        <author initials='G.' surname='Combs' fullname='Gerald Combs'>
            <organization>Wireshark</organization>
            <address>
                <email>gerald@wireshark.org</email>
            </address>
        </author>
        <author initials='G.' surname='Harris' fullname='Guy Harris'>
            <organization></organization>
            <address>
                <email>guy@alum.mit.edu</email>
            </address>
        </author>
        <date year='2016'/>
    </front>
</reference>

<reference anchor='pcap' target='http://www.tcpdump.org/'>
    <front>
        <title>PCAP</title>
        <author>
            <organization>tcpdump.org</organization>
        </author>
        <date year='2016'/>
    </front>
</reference>

<reference anchor='rrtypes' target='http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4'>
    <front>
        <title>RR types</title>
        <author>
            <organization>IANA</organization>
        </author>
        <date year='2016'/>
    </front>
</reference>

{backmatter}


# CDDL

    ; CDDL specification of the file format for C-DNS, 
    ; which describes a collection of DNS Q/R data items.

    File = [
        file-type-id  : tstr,          ; "C-DNS"
        file-preamble : FilePreamble,
        file-blocks   : [* Block],
    ]

    FilePreamble = {
        format-version  => uint, ; 1
        ? configuration => Configuration,
        ? generator-id  => tstr,
        ? host-id       => tstr,
    }

    format-version = 0
    configuration  = 1
    generator-id   = 2
    host-id        = 3

    Configuration = {
        ? query-timeout    => uint,
        ? skew-timeout     => uint,
        ? snaplen          => uint,
        ? promisc          => uint,
        ? interfaces       => [* tstr],
        ? vlan-ids         => [* uint],
        ? filter           => tstr,
        ? query-options    => uint,    ; See below
        ? response-options => uint,
        ? accept-rr-types  => [* tstr],
        ? ignore-rr-types  => [* tstr],
    }

    ; query-options and response-options are bitmasks. A bit set adds in the
    ; specified sections.
    ;
    ; second & subsequent question sections = 1
    ; answer sections = 2
    ; authority sections = 4
    ; additional sections = 8

    query-timeout    = 0
    skew-timeout     = 1
    snaplen          = 2
    promisc          = 3
    interfaces       = 4
    vlan-ids         = 5
    filter           = 6
    query-options    = 7
    response-options = 8
    accept-rr-types  = 9;
    ignore-rr-types  = 10;


    Block = {
        preamble             => BlockPreamble,
        ? statistics         => BlockStatistics, ; Much of this could be derived
        tables               => BlockTables,
        queries              => [* QueryResponse],
        address-event-counts => [* AddressEventCount],
    }

    preamble             = 0
    statistics           = 1
    tables               = 2
    queries              = 3
    address-event-counts = 4

    BlockPreamble = {
        start-time => Timeval
    }

    start-time = 1

    Timeval = [
        seconds      : uint,
        microseconds : uint,
    ]

    BlockStatistics = {
        ? total-packets        => uint,
        ? total-pairs          => uint,
        ? unmatched_queries    => uint,
        ? unmatched_responses  => uint,
        ? malformed-packets    => uint,
        ? non-dns-packets      => uint,
        ? out-of-order-packets => uint,
        ? missing-pairs        => uint,
        ? missing-packets      => uint,
        ? missing-non-dns      => uint,
    }

    total-packets        = 0
    total-pairs          = 1
    unmatched_queries    = 2
    unmatched_responses  = 3
    malformed-packets    = 4
    non-dns-packets      = 5
    out-of-order-packets = 6
    missing-pairs        = 7
    missing-packets      = 8
    missing-non-dns      = 9

    BlockTables = {
        ip-address => [* bstr],
        classtype  => [* ClassType],
        name-rdata => [* bstr],            ; Holds both Name RDATA and RDATA
        query_sig  => [* QuerySignature]
        ? qlist    => [* QuestionList],
        ? qrr      => [* Question],
        ? rrlist   => [* RRList],
        ? rr       => [* RR],
    }

    ip-address = 0
    classtype  = 1
    name-rdata = 2
    query_sig  = 3
    qlist      = 4
    qrr        = 5
    rrlist     = 6
    rr         = 7

    QueryResponse = {
        time-useconds         => uint,        ; Time offset from earliest record
        client-address-index  => uint,
        client-port           => uint,
        transaction-id        => uint,
        query-signature-index => uint,
        ? client-hoplimit     => uint,
        ? delay-useconds      => int,        ; Times may be -ve at capture
        ? query-name-index    => uint,
        ? response-size       => uint,       ; DNS size of response
        ? query-extended      => QueryResponseExtended,
        ? response-extended   => QueryResponseExtended,
    }

    time-useconds         = 0
    client-address-index  = 1
    client-port           = 2
    transaction-id        = 3
    query-signature-index = 4
    client-hoplimit       = 5
    delay-useconds        = 6
    query-name-index      = 7
    response-size         = 8
    query-extended        = 9
    response-extended     = 10

    ClassType = {
        type  => uint,
        class => uint,
    }

    type  = 0
    class = 1

    QuerySignature = {
        server-address-index    => uint,
        server-port             => uint,
        transport-flags         => uint,
        qr-sig-flags            => uint,
        ? query-opcode          => uint,
        qr-dns-flags            => uint,
        ? query-rcode           => uint,
        ? query-classtype-index => uint,
        ? query-qd-count        => uint,
        ? query-an-count        => uint,
        ? query-ar-count        => uint,
        ? query-ns-count        => uint,
        ? edns-version          => uint,
        ? udp-buf-size          => uint,
        ? opt-rdata-index       => uint,
        ? response-rcode        => uint,
    }

    server-address-index  = 0
    server-port           = 1
    transport-flags       = 2
    qr-sig-flags          = 3
    query-opcode          = 4
    qr-dns-flags          = 5
    query-rcode           = 6
    query-classtype-index = 7
    query-qd-count        = 8
    query-an-count        = 9
    query-ar-count        = 10
    query-ns-count        = 11
    edns-version          = 12
    udp-buf-size          = 13
    opt-rdata-index       = 14
    response-rcode        = 15

    QuestionList = [
        * uint,                           ; Index of Question
    ]

    Question = {                          ; Second and subsequent questions
        name-index      => uint,          ; Index to a name in the name-rdata table
        classtype-index => uint,
    }

    name-index      = 0
    classtype-index = 1

    RRList = [
        * uint,                           ; Index of RR
    ]

    RR = {
        name-index      => uint,          ; Index to a name in the name-rdata table
        classtype-index => uint,
        ttl             => uint,
        rdata-index     => uint,          ; Index to RDATA in the name-rdata table
    }

    ttl         = 2
    rdata-index = 3

    QueryResponseExtended = {
        ? question-index   => uint,       ; Index of QuestionList
        ? answer-index     => uint,       ; Index of RRList
        ? authority-index  => uint,
        ? additional-index => uint,
    }

    question-index   = 0
    answer-index     = 1
    authority-index  = 2
    additional-index = 3

    AddressEventCount = {
        ae-type          => &AddressEventType,
        ? ae-code        => uint,
        ae-address-index => uint,
        ae-count         => uint,
    }

    ae-type          = 0
    ae-code          = 1
    ae-address-index = 2
    ae-count         = 3

    AddressEventType = (
        tcp-reset: 0,
        icmp-time-exceeded     : 1,
        icmp-dest-unreachable  : 2,
        icmpv6-time-exceeded   : 3,
        icmpv6-dest-unreachable: 4,
        icmpv6-packet-too-big  : 5,
    )


# DNS Name compression example

The basic algorithm, which follows the guidance in [@!RFC1035],
is simply to collect each name, and the offset in the packet
at which it starts, during packet construction. As each name is added, it is
offered to each of the collected names in order of collection, starting from
the first name. If labels at the end of the name can be replaced with a reference back
to part (or all) of the earlier name, and if the uncompressed part of the name
is shorter than any compression already found, the earlier name is noted as the
compression target for the name.

The following tables illustrate the process. In an example packet, the first 
name is example.com.

N | Name | Uncompressed | Compression Target
---:|:-----|:-----|:-----------
1 | example.com | | 

The next name added is bar.com. This is matched against example.com. The
com part of this can be used as a compression target, with the remaining
uncompressed part of the name being bar.

N | Name | Uncompressed | Compression Target
---:|:-----|:-----|:-----------
1 | example.com | | 
2 | bar.com | bar | 1 + offset to com

The third name added is www.bar.com. This is first matched against
example.com, and as before this is recorded as a compression target, with the
remaining uncompressed part of the name being www.bar. It is then matched
against the second name, which again can be a compression target. Because the
remaining uncompressed part of the name is www, this is an improved compression,
and so it is adopted.

N | Name | Uncompressed | Compression Target
---:|:-----|:-----|:-----------
1 | example.com | | 
2 | bar.com | bar | 1 + offset to com
3 | www.bar.com | www | 2

As an optimization, if a name is already perfectly compressed (in other words,
the uncompressed part of the name is empty), then no further names will be considered
for compression.

## NSD compression algorithm

Using the above basic algorithm the packet lengths of responses generated by
[NSD](https://www.nlnetlabs.nl/projects/nsd/) can be matched almost exactly. At the time of writing, a tiny number
(<.01%) of the reconstructed packets had incorrect lengths.

## Knot Authoritative compression algorithm

The [Knot Authoritative](https://www.knot-dns.cz/) name server uses different compression behavior, which is
the result of internal optimization designed to balance runtime speed with compression
size gains. In
brief, and omitting complications, Knot  Authoritative will only consider the QNAME and names
in the immediately preceding RR section in an RRSET as compression targets.

A set of smart heuristics as described below can be implemented to mimic this and while not
perfect it produces output nearly, but not quite, as good a match as with NSD.
The heuristics are:

1. A match is only perfect if the name is completely compressed AND the TYPE of the section in which the name occurs matches the TYPE of the name used as the compression target.
2. If the name occurs in RDATA:

    * If the compression target name is in a query, then only the first RR in an RRSET can use that name as a compression target.
    * The compression target name MUST be in RDATA.
    * The name section TYPE must match the compression target name section TYPE.
    * The compression target name MUST be in the immediately preceding RR in the RRSET.

Using this algorithm less than 0.1% of the reconstructed packets had incorrect lengths.

## Observed differences

In sample traffic collected on a root name server around 2-4% of responses generated by Knot
had different packet lengths to those produced by NSD.

# Comparison of Binary Formats

Several binary serialisation formats were considered, and for
completeness were also compared to JSON.

* [Apache Avro](https://avro.apache.org/). Data is stored according to
  a pre-defined schema. The schema itself is always included in the
  data file. Data can therefore be stored untagged, for a smaller
  serialisation size, and be written and read by an Avro library.
* [Google Protocol
  Buffers](https://developers.google.com/protocol-buffers/). Data is
  stored according to a pre-defined schema. The schema is used by a
  generator to generate code for encoding and decoding the data. Data
  can therefore be stored untagged, for a smaller serialisation size.
  The schema is not stored with the data, so unlike Avro cannot be
  read with a generic library.
* [CBOR](http://cbor.io). Defined in [@!RFC7049], this serialisation format
  is comparable to JSON but with a binary representation. It does not
  use a pre-defined schema, so data is always stored tagged. However,
  CBOR data schemas can be described using CDDL
  [@?I-D.greevenbosch-appsawg-cbor-cddl#09] and tools exist to verify
  data files conform to the schema.

A test program was written which reads input from an input PCAP file
and writes output using two basic structures; a simple structure,
where each query/response pair is represented in a single record
entry, and a block structure as described above, where query/responses
are collected into blocks and common data is reused.

The resulting output files were then compressed using a variety of common
general-purpose lossless compression tools to explore the
compressibility of the formats. The compression tools employed were:

* [snzip](https://github.com/kubo/snzip). A command line compression
  tool based on the [Google Snappy](http://google.github.io/snappy/)
  library.
* [lz4](http://lz4.github.io/lz4/). The command line
  compression tool from the reference C LZ4 implementation.
* [gzip](http://www.gzip.org/). The ubiquitous GNU zip tool.
* [zstd](http://facebook.github.io/zstd/). Compression using the Zstandard
  algorithm.
* [xz](http://tukaani.org/xz/). A popular compression tool noted for high
  compression.

In all cases the compression tools were run using their default settings.

Note that this draft does not mandate the use of compression, nor any
particular compression scheme, but it anticipates that in practice
output data will be subject to general-purpose compression, and so
this should be taken into consideration.

A capture of sample data from a root instance was used for the
comparison. The input file was 661.87Mb. The following table shows the
formatted size and size after compression (both in Mb), together with
the task resident set size (RSS) in kb and the user time in seconds
taken by the compression.

Format|File size|Comp.|Comp. size|RSS|User time
:-----|--------:|:----|---------:|--:|--------:
PCAP|661.87|snzip|212.48|2696|1.26
 | |lz4|181.58|6336|1.35
 | |gzip|153.46|1428|18.20
 | |zstd|87.07|3544|4.27
 | |xz|49.09|97416|160.79
||
JSON simple|4113.92|snzip|603.78|2656|5.72
 | |lz4|386.42|5636|5.25
 | |gzip|271.11|1492|73.00
 | |zstd|133.43|3284|8.68
 | |xz|51.98|97412|600.74
||
Avro simple|640.45|snzip|148.98|2656|0.90
 | |lz4|111.92|5828|0.99
 | |gzip|103.07|1540|11.52
 | |zstd|49.08|3524|2.50
 | |xz|22.87|97308|90.34
||
CBOR simple|764.82|snzip|164.57|2664|1.11
 | |lz4|120.98|5892|1.13
 | |gzip|110.61|1428|12.88
 | |zstd|54.14|3224|2.77
 | |xz|23.43|97276|111.48
||
PBuf simple|749.51|snzip|167.16|2660|1.08
 | |lz4|123.09|5824|1.14
 | |gzip|112.05|1424|12.75
 | |zstd|53.39|3388|2.76
 | |xz|23.99|97348|106.47
||
JSON block|519.77|snzip|106.12|2812|0.93
 | |lz4|104.34|6080|0.97
 | |gzip|57.97|1604|12.70
 | |zstd|61.51|3396|3.45
 | |xz|27.67|97524|169.10
||
Avro block|60.45|snzip|48.38|2688|0.20
 | |lz4|48.78|8540|0.22
 | |gzip|39.62|1576|2.92
 | |zstd|29.63|3612|1.25
 | |xz|18.28|97564|25.81
||
CBOR block|75.25|snzip|53.27|2684|0.24
 | |lz4|51.88|8008|0.28
 | |gzip|41.17|1548|4.36
 | |zstd|30.61|3476|1.48
 | |xz|18.15|97556|38.78
||
PBuf block|67.98|snzip|51.10|2636|0.24
 | |lz4|52.39|8304|0.24
 | |gzip|40.19|1520|3.63
 | |zstd|31.61|3576|1.40
 | |xz|17.94|97440|33.99

The above results are discussed in the following sections.

## Comparison with full PCAP files

An important first consideration is whether moving away from PCAP
offers significant benefits. The data show that compressed PCAP files
are significantly larger than even the simple binary encodings, and
the compression requires significantly more processor than compression
of other encodings.

## Simple versus block coding

The intention of the block coding is to perform data de-duplication on
query/response records within the block. The simple and block formats
above store exactly the same information for each query/response
record. This information is parsed from the DNS traffic in the input
PCAP file, and in all cases each field has an identifier and the field
data is typed.

The reduction in data size for the simple formats over the PCAP format
made by not recording all fields in the PCAP - for example, Ethernet
MAC addresses are not retained - is, in most cases, lost to the field
identifiers and data type information.

The data de-duplication on the block formats show an order of
magnitude reduction in the size of the format file size against the
simple formats. As would be expected, the compression tools are able
to find and exploit a lot of this duplication, but as the
de-duplication process uses knowledge of DNS traffic, it is able to
retain a size advantage. This advantage reduces as stronger
compression is applied, as again would be expected, but even with the
strongest compression applied the block formatted data remains around
75% of the size of the simple format and its compression requires
roughly a third of the CPU time.

## Binary versus text formats

Text data formats offer many advantages over binary formats,
particularly in the areas of ad-hoc data inspection and extraction. It
was therefore felt worthwhile to carry out a direct comparison,
implementing JSON versions of the simple and block formats.

Concentrating on JSON block format, the format files produced are a
significant fraction of an order of magnitude larger than binary
formats. The impact on file size after compression is as might be
expected from that starting point; the stronger compression produces
files that are 150% of the size of similarly compressed binary format,
and require over 4x more CPU to compress.

## Binary serialisation formats

### Implementation notes

* CBOR.  CBOR is a simple format, and simple to implement. The CBOR website
  lists implementations for 16 languages.
* Protocol Buffers. Code must be generated for a particular data schema to
  to read and write data using that schema. The Google code generator can
  currently generate code for encoding and decoding a schema for C++, Go,
  Java, Python, Ruby, C#, Objective-C, Javascript and PHP.
* Avro. Avro libraries are available for C, C++, C#, Java, Python, Ruby
  and PHP. Optionally tools are available for C++, Java and C# to generate
  code for encoding and decoding.

Avro and Protocol Buffers both allow storage of untagged data, but
because they rely on the data schema for this, their implementation is
considerably more complex than CBOR. Using Avro or Protocol Buffers in
an unsupported environment would require notably greater development
effort compared to CBOR.

### Performance

Concentrating again on the block formats, all three produce format
files that are close to an order of magnitude smaller that the
original PCAP.  Avro produces the smallest files and CBOR the
largest. The Avro file is 80% the size of CBOR files, with the
Protocol Buffers file 90% of the CBOR size.

Once compression is taken into account, the size difference
narrows. At medium compression (gzip), Avro is 96% and Protocol
Buffers 98% of CBOR size, and using strong compression Protocol
Buffers is the smallest and Avro the largest, with Protocol Buffers
being 98% and CBOR 99% the size of Avro, though CBOR and Protocol
Buffers require more compression CPU.

The measurements presented above do not include data on the CPU
required to generate the format files. The testbed program producing
the format files was coded in Python, and so absolute runtime figures
do not reflect attainable performance in native code. However, each
serialisation format was written from Python via native code
libraries, so the relative demands of each block format may be
assessed. The same input data as before was used, and resulted
in the following timings.

Format|RSS (Mb)|User time
:-----|-------:|--------:
Avro|639.28|1412.50
CBOR|644.41|1259.34
PBuf|640.98|1271.62

It appears, therefore, that Avro's advantage in compression CPU usage
is probably offset by a larger CPU requirement in writing Avro.

## Format choice

The above assessments lead us to the choice of a binary format file
using blocking.

As noted previously, this draft anticipates that output data will be
subject to compression, and this being the case there is no compelling
case for one particular binary serialisation format in terms of either
final file size or machine resources consumed.

The relative simplicity of CBOR implementation and consequent lack of
reliance on library and/or code generator availability, its IETF
standardisation, and its close resemblance to JSON and thus its
accessibility to a wider industry beyond IETF were felt to justify its
adoption for this use case.

## Block size choice

Given the choice of a CBOR format using blocking, the question arises
of what an appropriate default value for the maximum number of
query/response pairs in a block should be. This has two components;
what is the impact on performance of using different block sizes in
the format file, and what is the impact on the size of the format file
before and after compression.

The following table addresses the performance question, showing the
impact on the performance of a C++ program writing the file format
described in this draft, using the same input data as before. Format
size is in Mb, RSS in kb.

Block size|Format size|RSS|User time
---------:|----------:|--:|--------:
1000|133.46|612.27|15.25
5000|89.85|676.82|14.99
10000|76.87|752.40|14.53
20000|67.86|750.75|14.49
40000|61.88|736.30|14.29
80000|58.08|694.16|14.28
160000|55.94|733.84|14.44
320000|54.41|799.20|13.97

Increasing block size, therefore, tends to increase maximum RSS a
little, with no significant effect (if anything a small reduction) on
CPU consumption.

The following figure plots the effect of increasing block size on output file size for different compressions.

![Figure showing effect of block size on file size (PNG)](https://github.com/dns-stats/draft-dns-capture-format/blob/master/file-size-versus-block-size.png)

![Figure showing effect of block size on file size (SVG)](https://github.com/dns-stats/draft-dns-capture-format/blob/master/file-size-versus-block-size.svg)

From the above, there is obviously scope for tuning the default block
size to the compression being employed, traffic loads, frequency of
output file rollover etc. Using a strong compression, block sizes over
10,000 query/response pairs would seem to offer limited improvements.

# Notes to implementors

## Malformed packets

In the presence of malformed packets where one or more of QDCOUNT, ANCOUNT, NSCOUNT and ARCOUNT do not match the RRs that can be successfully
decoded, the query signature should contain the values of the counts from the DNS header, and the query/response record should contain
the successfully decoded RRs. Beware, therefore, that the counts as recorded are not a reliable guide to the number of RRs associated with
the query/response.

## Block preamble timestamp

The timestamp in the block preamble gives the timestamp of the earliest query/response or malformed packet record
in the block. Query/response records and malformed packet records specify their timestamp as an offset from this timestamp.
This offset is always positive. Since, as already noted above in (#data-collection), packet capture libraries
do not necessarily provide packets in strict chronological order, the earliest item in the block will not necessarily
be the first item.
