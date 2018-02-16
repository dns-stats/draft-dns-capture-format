%%%
    Title = "C-DNS: A DNS Packet Capture Format"
    abbrev = "C-DNS: A DNS Packet Capture Format"
    category = "std"
    docName= "draft-ietf-dnsop-dns-capture-format-05"
    ipr = "trust200902"
    area = "Operations Area"
    workgroup = "dnsop"
    keyword = ["DNS"]
    date = 2018-02-16T00:00:00Z
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
DNS packets such as [@?I-D.daley-dnsxml], [@?I-D.hoffman-dns-in-json], but these are largely
aimed at producing convenient representations of single messages.

Many DNS operators may receive hundreds of thousands of queries per second on
single name server instance so
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
* A description of why CBOR [@!RFC7049] was chosen for this format (#choice-of-cbor)
* A conceptual overview of the C-DNS format (#cdns-format-overview)
* The definition of the C-DNS format for the collection of DNS messages (#cdns-format-detailed-description).
* Notes on converting C-DNS data to PCAP format (#cdns-to-pcap)
* Some high level implementation considerations for applications designed to
  produce C-DNS (#data-collection)

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [@!RFC2119].

"Packet" refers to individual IPv4 or IPv6 packets. Typically these are
UDP, but may be constructed from a TCP packet. "Message", unless otherwise
qualified, refers to a DNS payload extracted from a UDP or TCP data
stream.

The parts of DNS messages are named as they are in [@!RFC1035]. In specific,
the DNS message has five sections: Header, Question, Answer, Authority,
and Additional.

Pairs of DNS messages are called a Query and a Response.

# Data Collection Use Cases

In an ideal world, it would be optimal to collect full packet captures of all
packets going in or out of a name server. However, there are several
design choices or other limitations that are common to many DNS installations and operators.

* DNS servers are hosted in a variety of situations
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

1. The basic unit of data is a combined DNS Query and the associated Response (a "Q/R data item"). The same structure
will be used for unmatched Queries and Responses. Queries without Responses will be
captured omitting the response data. Responses without queries will be captured omitting the Query data (but using
the Question section from the response, if present, as an identifying QNAME).

    * Rationale: A Query and Response represents the basic level of a clients interaction with the server.
      Also, combining the Query and Response into one item often reduces storage requirements due to
      commonality in the data of the two messages.

2. All fields in each Q/R data item will be optional.

    * Rationale: Different users will have different requirements for data to be available for analysis.
      Users with minimal requirements should not have to pay the cost of recording full data, however this will
      limit the ability to perform certain kinds of data analysis and also reconstruct packet captures.
      For example, omitting the resource records from a Response will
      reduce C-DNS file size, and in principle responses can be synthesized if there is enough context.

3. Multiple data items will be collected into blocks in the format. Common data in a block will be abstracted and
referenced from individual data items by indexing. The maximum number of data items in a block will be configurable.

    * Rationale: This blocking and indexing provides a significant reduction in the volume of file data generated.
      Although this introduces complexity, it provides compression of the data that makes use of knowledge of the DNS message structure.
    * It is anticipated that the files produced can be subject to further compression using general purpose compression tools.
      Measurements show that blocking significantly reduces the CPU required to perform such strong compression. See (#simple-versus-block-coding).
    * [TODO: Further discussion of commonality between DNS messages e.g. common query signatures, a finite set of
      valid responses from authoritatives]

4. Traffic metadata can optionally be included in each block. Specifically, counts of some types of non-DNS packets
(e.g. ICMP, TCP resets) sent to the server may be of interest.

5. The wire format content of malformed DNS messages can optionally be recorded.

    * Rationale: Any structured capture format that does not capture the DNS payload byte for byte will be limited to some extent in
      that it cannot represent "malformed" DNS messages (see (#malformed-messages)). Only those messages that can be fully parsed and transformed into the
      structured format can be fully represented. Therefore it can greatly aid downstream analysis to have the wire format of the malformed DNS messages
      available directly in the C-DNS file.
      Note, however, this can result in rather misleading statistics. For example, a
      malformed query which cannot be represented in the C-DNS format will lead to the (well formed) DNS responses with error code
      FORMERR appearing as 'unmatched'.

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
* CBOR data schemas can be described using CDDL [@?I-D.ietf-cbor-cddl].

# C-DNS format overview

## Conceptual Overview

The following figures show purely schematic representations of the C-DNS format to convey the high-level
structure of the C-DNS format. (#cdns-format-detailed-description) provides a detailed discussion of the CBOR representation
and individual elements.

![Figure showing the C-DNS format (PNG)](https://github.com/dns-stats/draft-dns-capture-format/blob/master/draft-05/cdns_format.png)

![Figure showing the C-DNS format (SVG)](https://github.com/dns-stats/draft-dns-capture-format/blob/master/draft-05/cdns_format.svg)

![Figure showing the Q/R data item and Block tables format (PNG)](https://github.com/dns-stats/draft-dns-capture-format/blob/master/draft-05/qr_data_format.png)

![Figure showing the Q/R data item and Block tables format (SVG)](https://github.com/dns-stats/draft-dns-capture-format/blob/master/draft-05/qr_data_format.svg)

A C-DNS file begins with a file header containing a file-type-id identifier and
a file-preamble. The file-preamble contains information on the file format version and an array of block-parameters items
(the contents of which include collection and storage parameters used for one or more blocks).

The file header is followed by a series of data blocks.

A block consists of a block header, containing a preamble item, various tables of common data,
and some statistics for the traffic received over the block. The block header
is then followed by a list of the Q/R data items detailing the queries and responses
received during processing of the block input. The list of Q/R data items is in turn followed
by a list of per-client counts of particular IP events and a list of malformed messages
that occurred during collection of the block data.

The exact nature of the DNS data will affect what block size is the best fit,
however sample data for a root server indicated that block sizes up to
10,000 Q/R data items give good results. See (#block-size-choice) for more details.

### Block parameters

An array of block-parameters items is stored in the file header (with
a minimum of one item at index 0) in order to support use cases such as wanting
to merge C-DNS files from different sources. The block header preamble item then
contains an optional index for the block-parameters item that applies for that
block; if not present the index defaults to 0. Hence, in effect, a global
block-parameters item is defined which can then be overridden per block.

## Storage parameters

The block-parameters item includes a
storage parameters item - this contains information about the specific data
fields stored in the C-DNS file.

These parameters include:

* The sub-second timing resolution used by the data.
* Information (hints) on which optional data items can be expected to appear in the data. See (#optional-data-items).
* Recorded OPCODES and RR types. See (#optional-rrs-and-opcodes).
* Flags indicating whether the data is sampled or anonymised. See #sampling-and-anonymisation).
* Client and server IPv4 and IPv6 address prefixes. See (#ip-address-storage)

### Optional data items

To enable applications to store data to their precise requirements in
as space-efficient manner as possible, all fields in the following arrays are optional

* Query/Response
* Query Signature
* Malformed messages

In other words, an
application can choose to omit any data item that is not required for
its use case. In addition, implementations may be configured to not record all
RRs, or only record messages with certain OPCODES.

This does, however, mean that a consumer of a C-DNS file faces two problems:

1. How can it quickly determine whether a file contains the data items it requires to complete a particular task (e.g. reconstructing query traffic or performing a specific piece of data analysis)?

2. How can it determine if a data item is not present because it was
  a. explicitly not recorded or
  b. not present in the original data stream/the data item was not available to the collecting application

For example, an application capturing C-DNS data from within a nameserver
implementation is unlikely to be able to record the client-hoplimit. Or, if
there is no query ARCount recorded and no query OPT RDATA recorded, is that
because no query contained an OPT RR, or because that data was not stored?

The storage parameters hints therefore specify whether the writer of
the file recorded each data item if it was present. An application consuming
that file can then use
these to quickly determine whether the input data is rich enough for its needs.

QUESTION: Should the items within certain arrays also be optional e.g. within the RR array should all of Name index, ClassType, TTL and RDATA be optional

### Optional RRs and OPCODES

Also included in the storage parameters is an explicit list of the RR types and
OPCODES that were recorded. Using an explicit list removes any ambiguity about
whether the OPCODE/RR type was not recognised by the collecting implementation
or whether it was specifically configured not to record it.

For the case of unrecognised OPCODES the message may be parsable (for example,
if it has a format similar enough to the one described in [@!RFC1035]) or it
may not. Similarly for unrecognised RR types the RDATA can still be stored, but
the collector will not be able to process it to remove, for example, name
compression pointers.

QUESTION: Should the storage parameters additionally define whether unrecognised
OPCODES/RR types are stored ?

### Sampling and Anonymisation

The format contains flags that can be used to indicate if the data is either
anonymised or produced from sample data.

QUESTION: Should fields be added to indicate the sampling/anonymisation method
used and if so should text strings be used?

QUESTION: Should there be another flag to indicate that names have
been normalised (e.g. converted to uniform case)?

### IP Address storage

If IP address prefixes are given, only the prefix bits of addresses
are stored. For example, if a client IPv4 prefix of 16 is specified, a
client address of 192.0.2.1 will be stored as 0xc000 (192.0), reducing
address storage space requirements.

# C-DNS format detailed description

The CDDL definition for the C-DNS format is given in (#cddl).

## Map quantities and indexes

All map keys are integers with values specified in the CDDL. String keys
would significantly bloat the file size.

All key values specified are positive integers under 24,
so their CBOR representation is a single byte.

All maps have have additional implementation-specific
entries. Negative integer map keys are reserved for these values.  Key
values from -1 to -24 also have a single byte CBOR representation, so
such implementation-specific extensions are not at any space
efficiency disadvantage.

An item described as an index is the index of the data item in the referenced table.
Indexes are 0-based.

## Tabular representation

The following sections present the C-DNS specification in tabular format with a detailed description of each item.

In all quantities that contain bit flags, bit 0 indicates the least significant bit.

For the sake of brevity, the following conventions are used in the tables:

* The column O marks whether items in a map are optional.
  * O - Optional. The item may be omitted.
  * M - Mandatory. The item must be present.
* The column T gives the CBOR data type of the item.
  * U - Unsigned integer
  * I - Signed integer
  * B - Byte string
  * T - Text string
  * M - Map
  * A - Array

In the case of maps and arrays, more information on the type of each value is given in the description.

## File header contents

The file header contains the following:

Field | O | T | Description
:-----|:-:|:-:|:-----------
file-type-id | M | T | String "C-DNS" identifying the file type.
||
file-preamble | M | M | Version and parameter information for the whole file. See (#file-preamble-contents).
||
file-blocks | M | A | The data blocks. The array may be empty if the file contains no data. See (#block-contents).

## File preamble contents

The file preamble contains the following:

Field | O | T | Description
:-----|:-:|:-:|:-----------
major-format-version | M | U | Unsigned integer '1'. The major version of format used in file.
||
minor-format-version | M | U | Unsigned integer '0'. The minor version of format used in file.
||
private-version | O | U | Version indicator available for private use by applications.
||
block-parameters | M | A | List of parameters relating to one or more blocks. The preamble to each block indicates which array entry applies to the block. The array must contain at least one entry. See (#block-parameter-contents).

### Block parameter contents

A single item of block parameters contains the following maps.

Field | O | T | Description
:-----|:-:|:-:|:-----------
storage | M | M | Parameters relating to data storage in the block. See (#storage-parameter-contents).
||
collection | O | M | Parameters relating to collection of the data in the block. See (#collection-parameter-contents).

#### Storage parameter contents

The storage parameters contains the following items.

Field | O | T | Description
:-----|:-:|:-:|:-----------
ticks-per-second | M | U | Sub-second timing is recorded in ticks. This specifies the number of ticks in a second.
||
max-block-items | M | U | The maximum number of each record type (queries, address event counts or malformed messages) in a block. An indication of the resources needed to process the file.
||
table-field-hints | M | M | Collection of data field present hints. See (#storage-parameter-table-field-hints).
||
opcodes | M | A | List of OPCODES (unsigned integers) recorded by the collection application.
||
rr-types | M | A | List of RR types (unsigned integers) recorded by the collection application.
||
storage-flags | O | U | Bit flags indicating attributes of collected data.
 | | | Bit 0. The data has been anonymised.
 | | | Bit 1. The data is sampled data.
||
client-address -prefix-ipv4 | O | U | IPv4 client address prefix length. If specified, only the address prefix bits are stored.
||
client-address -prefix-ipv6 | O | U | IPv6 client address prefix length. If specified, only the address prefix bits are stored.
||
server-address -prefix-ipv4 | O | U | IPv4 server address prefix length. If specified, only the address prefix bits are stored.
||
server-address -prefix-ipv6 | O | U | IPv6 server address prefix length. If specified, only the address prefix bits are stored.


##### Storage parameter table field hints

These hints indicate which fields the collecting application records.

Field | O | T | Description
:-----|:-:|:-:|:-----------
query-response | M | U | Hints indicating which query response data fields are collected. If the data field is collected the bit is set.
 | | | Bit 0. time-offset
 | | | Bit 1. client-address-index
 | | | Bit 2. client-port
 | | | Bit 3. transaction-id
 | | | Bit 4. query-signature-index
 | | | Bit 5. client-hoplimit
 | | | Bit 6. response-delay
 | | | Bit 7. query-name-index
 | | | Bit 8. query-size
 | | | Bit 9. response-size
 | | | Bit 10. response-processing-data
 | | | Bit 11. query-question-sections
 | | | Bit 12. query-answer-sections
 | | | Bit 13. query-authority-sections
 | | | Bit 14. query-additional-sections
 | | | Bit 15. response-answer-sections
 | | | Bit 16. response-authority-sections
 | | | Bit 17. response-additional-sections
 | | |
query-signature | M | U | Hints indicating which query signature data fields are collected. If the data field is collected the bit is set.
 | | | Bit 0. server-address
 | | | Bit 1. server-port
 | | | Bit 2. transport-flags
 | | | Bit 3. qr-type
 | | | Bit 4. qr-sig-flags
 | | | Bit 5. query-opcode
 | | | Bit 6. dns-flags
 | | | Bit 7. query-rcode
 | | | Bit 8. query-class-type
 | | | Bit 9. query-qdcount
 | | | Bit 10. query-ancount
 | | | Bit 11. query-nscount
 | | | Bit 12. query-arcount
 | | | Bit 13. query-edns-version
 | | | Bit 14. query-udp-size
 | | | Bit 15. query-opt-rdata
 | | | Bit 16. response-rcode
 | | |
other-tables | M | U | Hints indicating which other tables are collected. If the table is collected the bit is set.
 | | | Bit 0. Malformed messages
 | | | Bit 1. Address event counts
 | | |
implementation -dependent | O | U | Collection hints for implementation-specific items. Values of this field are implementation specific.

### Collection parameter contents

The collection parameters contain the following items.

These parameters have no default. If they do not appear, nothing can be inferred about their value.

Field | O | T | Description
:-----|:-:|:-:|:-----------
query-timeout | O | U | To be matched with a query, a response must arrive within this number of seconds.
||
skew-timeout | O | U | The network stack may report a response before the corresponding query. A response is not considered to be missing a query until after this many micro-seconds.
||
snaplen | O | U | Collect up to this many bytes per packet.
||
promisc | O | U | 1 if promiscuous mode was enabled on the interface, 0 otherwise.
||
interfaces | O | A | Identifiers (text strings) of the interfaces used for collection.
||
server-addresses | O | A | Server collection IP addresses (byte strings). Hint for downstream analysers; does not affect collection.
||
vlan-ids | O | A | Identifiers (unsigned integers) of VLANs selected for collection.
||
filter | O | T | `tcpdump` [@pcap] style filter for input.
||
generator-id | O | T | String identifying the collection method.
||
host-id | O | T | String identifying the collecting host. Empty if converting an existing packet capture file.

## Block contents

Each block contains the following items.

Field | O | T | Description
:-----|:-:|:-:|:-----------
preamble | M | M | Overall information for the block. See (#block-preamble-contents).
||
statistics | O | M | Statistics about the block. See (#block-statistics-contents).
||
tables | O | M | The tables containing data referenced by individual Q/R data items. See (#block-table-contents).
||
queries | O | A | Details of individual Q/R data items. See (#queryresponse-data). If present, the array must not be empty.
||
address-event -counts | O | A | Per client counts of ICMP messages and TCP resets. See (#address-event-count-contents). If present, the array must not be empty.
||
malformed-messages | O | A | Wire contents of malformed DNS messages. See (#malformed-message-record-contents). If present, the array must not be empty.

### Block preamble contents

The block preamble map contains overall information for the block.

Field | O | T | Description
:-----|:-:|:-:|:-----------
earliest-time | O | A | A timestamp (2 unsigned integers) for the earliest record in the block. The first integer is the number of seconds since the Posix epoch (`time_t`). The second integer is the number of ticks since the start of the second. This timestamp can only be omitted if all block items containing a time offset from the start of the block are also omitted.
| | |
block-parameters-index | O | U | The index of the block parameters applicable to this block. If not present, index 0 is used. See (#block-parameter-contents).

### Block statistics contents

The block statistics section contains some basic statistical information about the block. All items are optional.

Field | O | T | Description
:-----|:-:|:-:|:-----------
total-messages | O | U | Total number of DNS messages processed from the input traffic stream during collection of the block data.
| | |
total-pairs | O | U | Total number of Q/R data items in the block.
| | |
unmatched-queries | O | U | Number of unmatched queries in the block.
| | |
unmatched-responses | O | U | Number of unmatched responses in the block.
| | |
malformed-messages | O | U | Number of malformed messages found in input for the block.

### Block table contents

The block table map contains the block tables. Each element, or table,
is an array which, if present, must not be empty.

The item `qlist` contains indexes to values in the `qrr`
item. Therefore, if `qlist` is present, `qrr` must also be
present. Similarly, if `rrlist` is present, `rr` must also be present.

The map contains the following items.

Field | O | T | Description
:-----|:-:|:-:|:-----------
ip-address | O | A | IP addresses (byte strings), in network byte order. If client or server address prefixes are set, only the address prefix bits are stored. Each string is therefore up to 4 bytes long for an IPv4 address, or up to 16 bytes long for an IPv6 address. See (#storage-parameter-contents).
| | |
classtype | O | A | CLASS/TYPE items. See (#classtype-table-contents).
| | |
name-rdata | O | A | NAME and RDATA data (byte strings). Each entry is the contents of a single NAME or RDATA. Note that NAMEs, and labels within RDATA contents, are full domain names or labels; no DNS style name compression is used on the individual names/labels within the format.
| | |
query-sig | O | A | Query signatures. See (#query-signature-table-contents).
| | |
qlist | O | A | Question lists (arrays of unsigned integers). Each entry in a list is an index to question data in the qrr table.
| | |
qrr | O | A | Question data. Each entry is the contents of a single question, where a question is the second or subsequent question in a query. See (#question-table-contents).
| | |
rrlist | O | A | RR lists (arrays of unsigned integers). Each entry in a list is an index to RR data in the rr table.
| | |
rr | O | A | RR data. Each entry is the contents of a single RR. See (#resource-record-rr-table-contents).
| | |
malformed-data | O | A | Malformed message contents. Each entry is the contents of a single malformed message.  See (#malformed-data-table-contents).

#### CLASS/TYPE table contents

The table `classtype` holds pairs of RR CLASS and TYPE values. Each item in the table is a CBOR map.

Field | O | T | Description
:-----|:-:|:-:|:-----------
type | M | U | TYPE value.
||
class | M | U | CLASS value.

#### Query Signature table contents

The table `query-sig` holds elements of the Q/R data item that are
often common between multiple individual Q/R data items. Each item in
the table is a CBOR map.

Field | O | T | Description
:-----|:-:|:-:|:-----------
server-address -index | O | U | The index in the IP address table of the server IP address. See (#block-table-contents).
||
server-port | O | U | The server port.
||
transport-flags | O | U | Bit flags describing the transport used to service the query.
 | | | Bit 0. IP version. 0 = IPv4, 1 = IPv6
 | | | Bit 1-4. Transport. 0 = UDP, 1 = TCP, 2 = TLS, 3 = DTLS.
 | | | Bit 5. Trailing bytes in query payload. The DNS query message in the UDP or TCP payload was followed by some additional bytes, which were discarded.
||
qr-type | O | U | Type of Query/Response transaction.
 | | | 0 = Stub. A query from a stub resolver.
 | | | 1 = Client. An incoming query to a recursive resolver.
 | | | 2 = Resolver. A query sent from a recursive resolver to an authorative resolver.
 | | | 3 = Authorative. A query to an authorative resolver.
 | | | 4 = Forwarder. A query sent from a recursive resolver to an upstream recursive resolver.
 | | | 5 = Tool. A query sent to a server by a server tool.
||
qr-sig-flags | O | U | Bit flags indicating information present in this Q/R data item.
 | | | Bit 0. 1 if a Query is present.
 | | | Bit 1. 1 if a Response is present.
 | | | Bit 2. 1 if one or more Question is present.
 | | | Bit 3. 1 if a Query is present and it has an OPT Resource Record.
 | | | Bit 4. 1 if a Response is present and it has an OPT Resource Record.
 | | | Bit 5. 1 if a Response is present but has no Question.
||
query-opcode | O | U | Query OPCODE.
||
qr-dns-flags | O | U | Bit flags with values from the Query and Response DNS flags. Flag values are 0 if the Query or Response is not present.
 | | | Bit 0. Query Checking Disabled (CD).
 | | | Bit 1. Query Authenticated Data (AD).
 | | | Bit 2. Query reserved (Z).
 | | | Bit 3. Query Recursion Available (RA).
 | | | Bit 4. Query Recursion Desired (RD).
 | | | Bit 5. Query TrunCation (TC).
 | | | Bit 6. Query Authoritative Answer (AA).
 | | | Bit 7. Query DNSSEC answer OK (DO).
 | | | Bit 8. Response Checking Disabled (CD).
 | | | Bit 9. Response Authenticated Data (AD).
 | | | Bit 10. Response reserved (Z).
 | | | Bit 11. Response Recursion Available (RA).
 | | | Bit 12. Response Recursion Desired (RD).
 | | | Bit 13. Response TrunCation (TC).
 | | | Bit 14. Response Authoritative Answer (AA).
||
query-rcode | O | U | Query RCODE. If the Query contains OPT, this value incorporates any EXTENDED_RCODE_VALUE.
||
query-classtype -index | O | U | The index in the CLASS/TYPE table of the CLASS and TYPE of the first Question. See (#block-table-contents).
||
query-qd-count | O | U | The QDCOUNT in the Query, or Response if no Query present.
||
query-an-count | O | U | Query ANCOUNT.
||
query-ns-count | O | U | Query NSCOUNT.
||
query-ar-count | O | U | Query ARCOUNT.
||
edns-version | O | U | The Query EDNS version.
||
udp-buf-size | O | U | The Query EDNS sender's UDP payload size.
||
opt-rdata-index | O | U | The index in the NAME/RDATA table of the OPT RDATA. See (#block-table-contents).
||
response-rcode | O | U | Response RCODE. If the Response contains OPT, this value incorporates any EXTENDED_RCODE_VALUE.

QUESTION: Currently we collect OPT RDATA as a blob as this is consistent with re-uses the generic mechanism for RDATA storage. Should we break individual EDNS(0) options out and store then individually in new Block table? This would potentially allow us to exploit option commonality and also make anonymising ECS client subnet easier.

#### Question table contents

The table `qrr` holds details on individual Questions in a Question
section. Each item in the table is a CBOR map containing a single
Question.

Field | O | T | Description
:-----|:-:|:-:|:-----------
name-index | M | U | The index in the NAME/RDATA table of the QNAME. See (#block-table-contents).
||
classtype-index | M | U | The index in the CLASS/TYPE table of the CLASS and TYPE of the Question. See (#block-table-contents).

#### Resource Record (RR) table contents

The table `rr` holds details on individual Resource Records in RR
sections.

Field | O | T | Description
:-----|:-:|:-:|:-----------
name-index | M | U | The index in the NAME/RDATA table of the NAME. See (#block-table-contents).
||
classtype-index | M | U | The index in the CLASS/TYPE table of the CLASS and TYPE of the RR. See (#block-table-contents).
||
ttl | M | U | The RR Time to Live.
||
rdata-index | M | U | The index in the NAME/RDATA table of the RR RDATA. See (#block-table-contents).

#### Malformed data table contents

The table `malformed-data` holds content for malformed message
items in the block. Each item in the table is a CBOR map containing
the following items.

Field | O | T | Description
:-----|:-:|:-:|:-----------
server-address -index | O | U | The index in the IP address table of the server IP address. See (#block-table-contents).
||
server-port | O | U | The server port.
||
transport-flags | O | U | Bit flags describing the transport used to service the query. Bit 0 is the least significant bit.
 | | | Bit 0. IP version. 0 = IPv4, 1 = IPv6
 | | | Bit 1-4. Transport. 0 = UDP, 1 = TCP, 2 = TLS, 3 = DTLS.
||
message-content | O | B | The raw contents of the DNS message.

<!-- Evade mmark bug -->

## Query/Response data

The block Q/R data is a CBOR array of individual Q/R data items. Each
item in the array is a CBOR map containing details on the individual
Q/R data item.

Note that there is no requirement that the elements of the Q/R array are presented in strict chronological order.

Field | O | T | Description
:-----|:-:|:-:|:-----------
time-offset | O | U | Q/R timestamp as an offset in ticks from the Block preamble Timestamp. The timestamp is the timestamp of the Query, or the Response if there is no Query.
||
client-address-index | O | U | The index in the IP address table of the client IP address. See (#block-table-contents).
||
client-port | O | U | The client port.
||
transaction-id | O | U | DNS transaction identifier.
||
query-signature-index | O | U | The index of the Query Signature table record for this data item. See (#block-table-contents).
||
client-hoplimit | O | U | The IPv4 TTL or IPv6 Hoplimit from the Query packet.
||
response-delay | O | I | The time difference between Query and Response, in ticks. Only present if there is a query and a response. The delay can be negative if the network stack/capture library returns packets out of order.
||
query-name-index | O | U | The index in the NAME/RDATA table of the QNAME for the first Question. See (#block-table-contents).
||
query-size | O | U | DNS query message size (see below).
||
response-size | O | U | DNS query message size (see below).
||
response-processing -data | O | M | Data on response processing. See (#response-processing-data-contents).
||
query-extended | O | M | Extended Query data. See (#extended-queryresponse-data-contents).
||
response-extended | O | M | Extended Response data. See (#extended-queryresponse-data-contents).

The query-size and response-size fields hold the DNS message size. For UDP this is the size of the UDP payload that contained the DNS message. For TCP it is the size of the DNS message as specified in the two-byte message length header. Trailing bytes with queries are routinely observed in traffic to authoritative servers and this value allows a calculation of how many trailing bytes were present.

### Response processing data contents

The response processing data is information on the server processing that produced the response. It is a CBOR map as follows.

Field | O | T | Description
:-----|:-:|:-:|:-----------
bailiwick-index | O | U | The index in the name-data table of owner name for the response bailiwick. See (#block-table-contents).
||
processing-flags | O | U | Flags relating to response processing.
 | | | Bit 0. 1 if the response came from cache.

QUESTION: Should this be an item in the Query Signature?

### Extended Query/Response data contents

The Extended information is a CBOR map as follows. Each item in the
map is present only if collection of the relevant details is
configured.

Field | O | T | Description
:-----|:-:|:-:|:-----------
question-index | O | U | The index in the Questions list table of the entry listing any second and subsequent Questions in the Question section for the Query or Response. See (#block-table-contents).
||
answer-index | O | U | The index in the RR list table of the entry listing the Answer Resource Record sections for the Query or Response. See (#block-table-contents).
||
authority-index | O | U | The index in the RR list table of the entry listing the Authority Resource Record sections for the Query or Response. See (#block-table-contents).
||
additional-index | O | U | The index in the RR list table of the entry listing the Additional Resource Record sections for the Query or Response. See (#block-table-contents).

## Address Event Count contents

This table holds counts of various IP related events relating to traffic
with individual client addresses.

Field | O | T | Description
:-----|:-:|:-:|:-----------
ae-type | M | U | The type of event. The following events types are currently defined:
 | | | 0. TCP reset.
 | | | 1. ICMP time exceeded.
 | | | 2. ICMP destination unreachable.
 | | | 3. ICMPv6 time exceeded.
 | | | 4. ICMPv6 destination unreachable.
 | | | 5. ICMPv6 packet too big.
||
ae-code | O | U | A code relating to the event.
||
ae-address-index | M | U | The index in the IP address table of the client address. See (#block-table-contents).
||
ae-count | M | U | The number of occurrences of this event during the block collection period.

## Malformed message record contents

This optional table records the original wire format content of malformed messages. See (#malformed-messages).

Field | O | T | Description
:-----|:-:|:-:|:-----------
time-offset | O | U | Message timestamp as an offset in ticks from the Block preamble Timestamp.
||
client-address-index | O | U | The index in the IP address table of the client IP address. See (#block-table-contents).
||
client-port | O | U | The client port.
||
message-data-index | O | U | The index in the Malformed messages table of the message data for this message. See (#block-table-contents).

# Malformed Messages

In the context of generating a C-DNS file it is assumed that only
those DNS messages which can be parsed to produce a well-formed DNS
message are stored in the C-DNS format and that all other messages will be recorded (if at all) as malformed messages.

Parsing a well-formed message means as a minimum:

* The packet has a well-formed 12 byte DNS Header
* The section counts are consistent with the section contents
* All of the resource records can be parsed

In principle, packets that do not meet these criteria could be classified into two categories:

* Partially malformed: those packets which can be decoded sufficiently
to extract

    * a well-formed 12 byte DNS header (and therefore a DNS transaction ID)
    * the first Question in the Question section if QDCOUNT is greater than 0

but suffer other issues while parsing. This is the minimum information required to attempt Query/Response matching as described in (#matching-algorithm).

* Completely malformed: those packets that cannot be decoded to this extent.

An open question is whether there is value in attempting to process
partially malformed messages in an analogous manner to well formed
messages in terms of attempting to match them with the corresponding
query or response. This could be done by creating 'placeholder'
records during Query/Response matching with just the information
extracted as above. If the packet were then matched the resulting
C-DNS Q/R data item would include flags to indicate a malformed query
or response or both record (in addition to capturing the wire format
of the packet).

An advantage of this would be that it would result in more meaningful
statistics about matched packets because, for example, some partially
malformed queries could be matched to responses. However it would only
apply to those queries where the first Question is well formed. It
could also simplify the downstream analysis of C-DNS files and the
reconstruction of packet streams from C-DNS.

A disadvantage is that this adds complexity to the Query/Response
matching and data representation, could potentially lead to false
matches and some additional statistics would be required (e.g. counts
for matched-partially-malformed, unmatched-partially-malformed,
completely-malformed).

QUESTION: There has been no feedback to date requesting further work
on the processing partially malformed messages. The editors are
inclined not to include it in this version. It could be the subject
of a future extension.

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
* Malformed DNS messages if the wire format is not recorded
* Any Non-DNS messages that were in the original packet stream e.g. ICMP

Simple assumptions can be made on the reconstruction: fragmented and DNS-over-TCP messages
can be reconstructed into single packets and a single TCP session can be constructed
for each TCP packet.

Additionally, if malformed messages and Non-DNS packets are captured separately,
they can be merged with packet captures reconstructed from C-DNS to produce a more complete
packet stream.

## Name Compression

All the names stored in the C-DNS format are full domain names; no DNS style name compression is used
on the individual names within the format. Therefore when reconstructing a packet,
name compression must be used in order to reproduce the on the wire representation of the
packet.

[@!RFC1035] name compression works by substituting trailing sections of a name with a
reference back to the occurrence of those sections earlier in the message.
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
1. Each message is associated with transport metadata required to generate the Primary ID (see (#primary-id))
1. Each message has a well-formed DNS header of 12 bytes and (if present) the first Question in the Question section can be parsed to generate the Secondary ID (see below). As noted earlier, this requirement can result in a malformed query being removed in the pre-processing stage, but the correctly formed response with RCODE of FORMERR being present.

DNS messages are processed in the order they are delivered to the application.
It should be noted that packet capture libraries do not necessary provide packets in strict chronological order.

TODO: Discuss the corner cases resulting from this in more detail.

## Matching algorithm

A schematic representation of the algorithm for matching Q/R data items is shown in the following diagram:

![Figure showing the Query/Response matching algorithm format (PNG)](https://github.com/dns-stats/draft-dns-capture-format/blob/master/draft-05/packet_matching.png)

![Figure showing the Query/Response matching algorithm format (SVG)](https://github.com/dns-stats/draft-dns-capture-format/blob/master/draft-05/packet_matching.svg)

Further details of the algorithm are given in the following sections.

## Message identifiers

### Primary ID (required) {#primary-id}

A Primary ID is constructed for each message. It is composed of the following data:

1. Source IP Address
1. Destination IP Address
1. Source Port
1. Destination Port
1. Transport
1. DNS Message ID

### Secondary ID (optional) {#secondary-id}

If present, the first Question in the Question section is used as a secondary ID
for each message. Note that there may be well formed DNS queries that have a
QDCOUNT of 0, and some responses may have a QDCOUNT of 0 (for example, responses
with RCODE=FORMERR or NOTIMP). In this case the secondary ID is not used in matching.

## Algorithm Parameters

1. Query timeout
2. Skew timeout

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

# Implementation guidance

TODO: Topics in this section need further expansion.

## Optional data

When reading data where items required for reader function are
missing, readers may wish to provide configurable default values to be
used in their output.

## Trailing data in TCP

Clearify the impact of processing wire captures which includes
trailing data in TCP. What will appear trailing data, what will appear
as malformed messages?

## Limiting collection of RDATA

Implementations should consider providing a configurable maximum RDATA size for capture.
For example, to avoid memory issues when confronted with large XFR records.

# Implementation Status

[Note to RFC Editor: please remove this section and reference to [@RFC7942] prior to publication.]

This section records the status of known implementations of the
protocol defined by this specification at the time of posting of
this Internet-Draft, and is based on a proposal described in
[@RFC7942].  The description of implementations in this section is
intended to assist the IETF in its decision processes in
progressing drafts to RFCs.  Please note that the listing of any
individual implementation here does not imply endorsement by the
IETF.  Furthermore, no effort has been spent to verify the
information presented here that was supplied by IETF contributors.
This is not intended as, and must not be construed to be, a
catalog of available implementations or their features.  Readers
are advised to note that other implementations may exist.

According to [@RFC7942], "this will allow reviewers and working
groups to assign due consideration to documents that have the
benefit of running code, which may serve as evidence of valuable
experimentation and feedback that have made the implemented
protocols more mature.  It is up to the individual working groups
to use this information as they see fit".

## DNS-STATS Compactor

ICANN/Sinodun IT have developed an open source implementation called DNS-STATS Compactor.
The Compactor is a suite of tools which can capture DNS traffic (from either a
network interface or a PCAP file) and store it in the Compacted-DNS (C-DNS) file
format. PCAP files for the captured traffic can also be reconstructed. See
[Compactor](https://github.com/dns-stats/compactor/wiki).

This implementation:

* is mature but has only been deployed for testing in a single environment so is
not yet classified as production ready.

* covers the whole of the specification described in the -03 draft with the
exception of support for malformed messages ((#malformed-messages)) and pico second time resolution.
(Note: this implementation does allow malformed messages to be dumped to a PCAP file).

* is released under the Mozilla Public License Version 2.0.

* has a users mailing list available, see [dns-stats-users](https://mm.dns-stats.org/mailman/listinfo/dns-stats-users).

There is also some discussion of issues encountered during development available at
[Compressing Pcap Files](https://www.sinodun.com/2017/06/compressing-pcap-files/) and
[Packet Capture](https://www.sinodun.com/2017/06/more-on-debian-jessieubuntu-trusty-packet-capture-woes/).

This information was last updated on 29th of June 2017.

# IANA Considerations

None

# Security Considerations

Any control interface MUST perform authentication and encryption.

Any data upload MUST be authenticated and encrypted.

# Acknowledgements

The authors wish to thank CZ.NIC, in particular Tomas Gavenciak, for many useful discussions on binary
formats, compression and packet matching. Also Jan Vcelak and Wouter Wijngaards for discussions on
name compression and Paul Hoffman for a detailed review of the document and the C-DNS CDDL.

Thanks also to Robert Edmonds and Jerry Lundström for review.

Also, Miek Gieben for [mmark](https://github.com/miekg/mmark)

# Changelog

draft-ietf-dnsop-dns-capture-format-05

* Make all data items optional
* Variable sub-second timing granularity
* Record malformed messages
* Add implementation guidance
* Add response bailiwick and query response type (dnstap)

draft-ietf-dnsop-dns-capture-format-04

* Correct query-d0 to query-do in CDDL
* Clarify that map keys are unsigned integers
* Add Type to Class/Type table
* Clarify storage format in section 7.12

draft-ietf-dnsop-dns-capture-format-03

* Added an Implementation Status section

draft-ietf-dnsop-dns-capture-format-02

* Update qr_data_format.png to match CDDL
* Editorial clarifications and improvements

draft-ietf-dnsop-dns-capture-format-01

* Many editorial improvements by Paul Hoffman
* Included discussion of malformed message handling
* Improved Appendix C on Comparison of Binary Formats
* Now using C-DNS field names in the tables in section 8
* A handful of new fields included (CDDL updated)
* Timestamps now include optional picoseconds
* Added details of block statistics

draft-ietf-dnsop-dns-capture-format-00

* Changed dnstap.io to dnstap.info
* qr_data_format.png was cut off at the bottom
* Update authors address
* Improve wording in Abstract
* Changed DNS-STAT to C-DNS in CDDL
* Set the format version in the CDDL
* Added a TODO: Add block statistics
* Added a TODO: Add extend to support pico/nano. Also do this for Time offset and Response delay
* Added a TODO: Need to develop optional representation of malformed messages within C-DNS and what this means for packet matching.  This may influence which fields are optional in the rest of the representation.
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

~~~~~
; CDDL specification of the file format for C-DNS,
; which describes a collection of DNS messages and
; traffic meta-data.

;
; The overall structure of a file.
;
File = [
    file-type-id  : tstr .regexp "C-DNS",
    file-preamble : FilePreamble,
    file-blocks   : [* Block],
]

;
; The file preamble.
;
FilePreamble = {
    major-format-version => uint .eq 1,
    minor-format-version => uint .eq 0,
    ? private-version    => uint,
    block-parameters     => [+ BlockParameters],
}
major-format-version = 0
minor-format-version = 1
private-version      = 2
block-parameters     = 3

BlockParameters = {
    storage      => StorageParameters,
    ? collection => CollectionParameters,
}
storage    = 0
collection = 1

  StorageParameters = {
      ticks-per-second             => uint,
      max-block-items              => uint,
      table-field-hints            => TableFieldHints,
      opcodes                      => [+ uint],
      rr-types                     => [+ uint],
      ? storage-flags              => StorageFlags,
      ? client-address-prefix-ipv4 => uint,
      ? client-address-prefix-ipv6 => uint,
      ? server-address-prefix-ipv4 => uint,
      ? server-address-prefix-ipv6 => uint,
  }
  ticks-per-second           = 0
  max-block-items            = 1
  table-field-hints          = 2
  opcodes                    = 3
  rr-types                   = 4
  storage-flags              = 5
  client-address-prefix-ipv4 = 6
  client-address-prefix-ipv6 = 7
  server-address-prefix-ipv4 = 8
  server-address-prefix-ipv6 = 9

    ; A hint indicates if the collection method will output the
    ; field or will ignore the field if present.
    TableFieldHints = {
        query-response             => QueryResponseFieldHints,
        query-signature            => QuerySignatureFieldHints,
        other-tables               => OtherTableFieldHints,
        ? implementation-dependent => uint,
    }
    query-response           = 0
    query-signature          = 1
    other-tables             = 2
    implementation-dependent = 3

      QueryResponseFieldHintValues = &(
          time-offset                  : 0,
          client-address-index         : 1,
          client-port                  : 2,
          transaction-id               : 3,
          query-signature-index        : 4,
          client-hoplimit              : 5,
          response-delay               : 6,
          query-name-index             : 7,
          query-size                   : 8,
          response-size                : 9,
          response-processing-data     : 10,
          query-question-sections      : 11,    ; Second & subsequent questions
          query-answer-sections        : 12,
          query-authority-sections     : 13,
          query-additional-sections    : 14,
          response-answer-sections     : 15,
          response-authority-sections  : 16,
          response-additional-sections : 17,
      )
      QueryResponseFieldHints = uint .bits QueryResponseFieldHintValues

      QuerySignatureFieldHintValues =&(
          server-address     : 0,
          server-port        : 1,
          transport-flags    : 2,
          qr-type            : 3,
          qr-sig-flags       : 4,
          query-opcode       : 5,
          dns-flags          : 6,
          query-rcode        : 7,
          query-class-type   : 8,
          query-qdcount      : 9,
          query-ancount      : 10,
          query-arcount      : 11,
          query-nscount      : 12,
          query-edns-version : 13,
          query-udp-size     : 14,
          query-opt-rdata    : 15,
          response-rcode     : 16,
      )
      QuerySignatureFieldHints = uint .bits QuerySignatureFieldHintValues

      OtherTableFieldHintValues = &(
          malformed-messages-table   : 0,
          address-event-counts-table : 1,
      )
      OtherTableFieldHints = uint .bits OtherTableFieldHintValues

    StorageFlagValues = &(
        anonymised-data      : 0,
        sampled-data         : 1,
    )
    StorageFlags = uint .bits StorageFlagValues

  CollectionParameters = {
      ? query-timeout      => uint,
      ? skew-timeout       => uint,
      ? snaplen            => uint,
      ? promisc            => uint,
      ? interfaces         => [+ tstr],
      ? server-addresses   => [+ IPAddress], ; Hint for later analysis
      ? vlan-ids           => [+ uint],
      ? filter             => tstr,
      ? generator-id       => tstr,
      ? host-id            => tstr,
  }
  query-timeout      = 0
  skew-timeout       = 1
  snaplen            = 2
  promisc            = 3
  interfaces         = 4
  server-addresses   = 5
  vlan-ids           = 6
  filter             = 7
  generator-id       = 8
  host-id            = 9

;
; Data in the file is stored in Blocks.
;
Block = {
    preamble                => BlockPreamble,
    ? statistics            => BlockStatistics, ; Much of this could be derived
    ? tables                => BlockTables,
    ? queries               => [+ QueryResponse],
    ? address-event-counts  => [+ AddressEventCount],
    ? malformed-messages    => [+ MalformedMessage],
}
preamble              = 0
statistics            = 1
tables                = 2
queries               = 3
address-event-counts  = 4
malformed-messages    = 5

;
; The (mandatory) preamble to a block.
;
BlockPreamble = {
    ? earliest-time          => Timestamp,
    ? block-parameters-index => uint .default 0,
}
earliest-time          = 0
block-parameters-index = 1

; Ticks are subsecond intervals. The number of ticks in a second is file/block
; metadata. Signed and unsigned tick types are defined.
ticks = int
uticks = uint

Timestamp = [
    timestamp-secs   : uint,
    timestamp-uticks : uticks,
]

;
; Statistics about the block contents.
;
BlockStatistics = {
    ? total-messages            => uint,
    ? total-pairs               => uint,
    ? total-unmatched-queries   => uint,
    ? total-unmatched-responses => uint,
    ? total-malformed-messages  => uint,
}
total-messages               = 0
total-pairs                  = 1
total-unmatched-queries      = 2
total-unmatched-responses    = 3
total-malformed-messages     = 4

;
; Tables of common data referenced from records in a block.
;
BlockTables = {
    ? ip-address     => [+ IPAddress],
    ? classtype      => [+ ClassType],
    ? name-rdata     => [+ bstr],            ; Holds both Name RDATA and RDATA
    ? query-sig      => [+ QuerySignature],
    ? QuestionTables,
    ? RRTables,
    ? malformed-data => [+ MalformedMessageData],
}
ip-address     = 0
classtype      = 1
name-rdata     = 2
query-sig      = 3
qlist          = 4
qrr            = 5
rrlist         = 6
rr             = 7
malformed-data = 8

IPv4Address = bstr .size 4
IPv6Address = bstr .size 16
IPAddress = IPv4Address / IPv6Address

ClassType = {
    type  => uint,
    class => uint,
}
type  = 0
class = 1

QuerySignature = {
    ? server-address-index  => uint,
    ? server-port           => uint,
    ? transport-flags       => TransportFlags,
    ? qr-type               => QueryResponseType,
    ? qr-sig-flags          => QueryResponseFlags,
    ? query-opcode          => uint,
    ? qr-dns-flags          => DNSFlags,
    ? query-rcode           => uint,
    ? query-classtype-index => uint,
    ? query-qd-count        => uint,
    ? query-an-count        => uint,
    ? query-ns-count        => uint,
    ? query-ar-count        => uint,
    ? edns-version          => uint,
    ? udp-buf-size          => uint,
    ? opt-rdata-index       => uint,
    ? response-rcode        => uint,
}
server-address-index  = 0
server-port           = 1
transport-flags       = 2
qr-type               = 3
qr-sig-flags          = 4
query-opcode          = 5
qr-dns-flags          = 6
query-rcode           = 7
query-classtype-index = 8
query-qd-count        = 9
query-an-count        = 10
query-ns-count        = 12
query-ar-count        = 12
edns-version          = 13
udp-buf-size          = 14
opt-rdata-index       = 15
response-rcode        = 16

  Transport = &(
      udp               : 0,
      tcp               : 1,
      tls               : 2,
      dtls              : 3,
  )

  TransportFlagValues = &(
      ip-version         : 0,     ; 0=IPv4, 1=IPv6
      ; Transport value bits 1-4
      query-trailingdata : 5,
  ) / (1..4)
  TransportFlags = uint .bits TransportFlagValues

  QueryResponseType = &(
      stub      : 0,
      client    : 1,
      resolver  : 2,
      auth      : 3,
      forwarder : 4,
      tool      : 5,
  )

  QueryResponseFlagValues = &(
      has-query               : 0,
      has-reponse             : 1,
      query-has-question      : 2,
      query-has-opt           : 3,
      response-has-opt        : 4,
      response-has-no-question: 5,
  )
  QueryResponseFlags = uint .bits QueryResponseFlagValues

  DNSFlagValues = &(
      query-cd   : 0,
      query-ad   : 1,
      query-z    : 2,
      query-ra   : 3,
      query-rd   : 4,
      query-tc   : 5,
      query-aa   : 6,
      query-do   : 7,
      response-cd: 8,
      response-ad: 9,
      response-z : 10,
      response-ra: 11,
      response-rd: 12,
      response-tc: 13,
      response-aa: 14,
  )
  DNSFlags = uint .bits DNSFlagValues

QuestionTables = (
    qlist => [+ QuestionList],
    qrr   => [+ Question]
)

  QuestionList = [+ uint]           ; Index of Question

  Question = {                      ; Second and subsequent questions
      name-index      => uint,      ; Index to a name in the name-rdata table
      classtype-index => uint,
  }
  name-index      = 0
  classtype-index = 1

RRTables = (
    rrlist => [+ RRList],
    rr     => [+ RR]
)

  RRList = [+ uint]                     ; Index of RR

  RR = {
      name-index      => uint,          ; Index to a name in the name-rdata table
      classtype-index => uint,
      ttl             => uint,
      rdata-index     => uint,          ; Index to RDATA in the name-rdata table
  }
  ; Other map key values already defined above.
  ttl         = 2
  rdata-index = 3

MalformedMessageData = {
    ? server-address-index   => uint,
    ? server-port            => uint,
    ? mm-transport-flags     => MalformedTransportFlags,
    ? mm-content             => bstr,   ; Raw packet contents
}
; Other map key values already defined above.
mm-transport-flags      = 2
mm-content              = 3

  MalformedTransportFlagValues = &(
      ip-version         : 0,     ; 0=IPv4, 1=IPv6
      ; Transport value bits 1-4
  ) / (1..4)
  MalformedTransportFlags = uint .bits MalformedTransportFlagValues

;
; A single query/response pair.
;
QueryResponse = {
    ? time-offset              => uticks,     ; Time offset from start of block
    ? client-address-index     => uint,
    ? client-port              => uint,
    ? transaction-id           => uint,
    ? query-signature-index    => uint,
    ? client-hoplimit          => uint,
    ? response-delay           => ticks,
    ? query-name-index         => uint,
    ? query-size               => uint,       ; DNS size of query
    ? response-size            => uint,       ; DNS size of response
    ? response-processing-data => ResponseProcessingData,
    ? query-extended           => QueryResponseExtended,
    ? response-extended        => QueryResponseExtended,
}
time-offset              = 0
client-address-index     = 1
client-port              = 2
transaction-id           = 3
query-signature-index    = 4
client-hoplimit          = 5
response-delay           = 6
query-name-index         = 7
query-size               = 8
response-size            = 9
response-processing-data = 10
query-extended           = 11
response-extended        = 12

ResponseProcessingData = {
    ? bailiwick-index  => uint,
    ? processing-flags => ResponseProcessingFlags,
}
bailiwick-index = 0
processing-flags = 1

  ResponseProcessingFlagValues = &(
      from-cache : 0,
  )
  ResponseProcessingFlags = uint .bits ResponseProcessingFlagValues

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

;
; Address event data.
;
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
    tcp-reset              : 0,
    icmp-time-exceeded     : 1,
    icmp-dest-unreachable  : 2,
    icmpv6-time-exceeded   : 3,
    icmpv6-dest-unreachable: 4,
    icmpv6-packet-too-big  : 5,
)

;
; Malformed messages.
;
MalformedMessage = {
    ? time-offset           => uticks,   ; Time offset from start of block
    ? client-address-index  => uint,
    ? client-port           => uint,
    ? message-data-index    => uint,
}
; Other map key values already defined above.
message-data-index = 3
~~~~~

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

    * At the time of writing, Avro libraries are available for C, C++, C#,
      Java, Python, Ruby and PHP. Optionally tools are available for C++,
      Java and C# to generate code for encoding and decoding.

* [Google Protocol
  Buffers](https://developers.google.com/protocol-buffers/). Data is
  stored according to a pre-defined schema. The schema is used by a
  generator to generate code for encoding and decoding the data. Data
  can therefore be stored untagged, for a smaller serialisation size.
  The schema is not stored with the data, so unlike Avro cannot be
  read with a generic library.

    * Code must be generated for a particular data schema to
      to read and write data using that schema. At the time of
      writing, the Google code generator can currently generate code
      for encoding and decoding a schema for C++, Go,
        Java, Python, Ruby, C#, Objective-C, Javascript and PHP.

* [CBOR](http://cbor.io). Defined in [@!RFC7049], this serialisation format
  is comparable to JSON but with a binary representation. It does not
  use a pre-defined schema, so data is always stored tagged. However,
  CBOR data schemas can be described using CDDL
  [@?I-D.ietf-cbor-cddl] and tools exist to verify
  data files conform to the schema.

    * CBOR is a simple format, and simple to implement. At the time of writing,
      the CBOR website lists implementations for 16 languages.

Avro and Protocol Buffers both allow storage of untagged data, but
because they rely on the data schema for this, their implementation is
considerably more complex than CBOR. Using Avro or Protocol Buffers in
an unsupported environment would require notably greater development
effort compared to CBOR.

A test program was written which reads input from a PCAP file
and writes output using one of two basic structures; either a simple structure,
where each query/response pair is represented in a single record
entry, or the C-DNS block structure.

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

`test.pcap`, a 662Mb capture of sample data from a root instance was
used for the comparison. The following table shows the
formatted size and size after compression (abbreviated to Comp. in the
table headers), together with the task resident set size (RSS) and the
user time taken by the compression. File sizes are in Mb, RSS in kb
and user time in seconds.

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
offers significant benefits.

The simple binary formats are typically larger than PCAP, even though
they omit some information such as Ethernet MAC addresses. But not only
do they require less CPU to compress than PCAP, the resulting
compressed files are smaller than compressed PCAP.

## Simple versus block coding

The intention of the block coding is to perform data de-duplication on
query/response records within the block. The simple and block formats
above store exactly the same information for each query/response
record. This information is parsed from the DNS traffic in the input
PCAP file, and in all cases each field has an identifier and the field
data is typed.

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

## Performance

Concentrating again on the block formats, all three produce format
files that are close to an order of magnitude smaller that the
original `test.pcap` file.  CBOR produces the largest files and Avro
the smallest, 20% smaller than CBOR.

However, once compression is taken into account, the size difference
narrows. At medium compression (with gzip), the size difference is 4%.
Using strong compression (with xz) the difference reduces to 2%, with Avro
the largest and Protocol Buffers the smallest, although CBOR and Protocol Buffers
require slightly more compression CPU.

The measurements presented above do not include data on the CPU
required to generate the format files. Measurements indicate
that writing Avro requires 10% more CPU than CBOR or Protocol Buffers.
It appears, therefore, that Avro's advantage in compression CPU usage
is probably offset by a larger CPU requirement in writing Avro.

## Conclusions

The above assessments lead us to the choice of a binary format file
using blocking.

As noted previously, this draft anticipates that output data will be
subject to compression. There is no compelling case for one particular
binary serialisation format in terms of either final file size or
machine resources consumed, so the choice must be largely based on
other factors. CBOR was therefore chosen as the binary serialisation format for
the reasons listed in (#choice-of-cbor).

## Block size choice

Given the choice of a CBOR format using blocking, the question arises
of what an appropriate default value for the maximum number of
query/response pairs in a block should be. This has two components;
what is the impact on performance of using different block sizes in
the format file, and what is the impact on the size of the format file
before and after compression.

The following table addresses the performance question, showing the
impact on the performance of a C++ program converting `test.pcap`
to C-DNS. File size is in Mb, resident set size (RSS) in kb.

Block size|File size|RSS|User time
---------:|--------:|--:|--------:
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
size to the compression being employed, traffic characteristics, frequency of
output file rollover etc. Using a strong compression, block sizes over
10,000 query/response pairs would seem to offer limited improvements.
