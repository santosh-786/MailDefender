import hashlib

class IOCGraphMapper:
    @staticmethod
    def _stable_id(prefix, value):
        return f"{prefix}_{hashlib.md5(value.encode()).hexdigest()[:12]}"

    @staticmethod
    def map_relationships(parsed_data, url_results, attachment_results, body_iocs=None):
        nodes = []
        edges = []
        seen_nodes = set()

        email_id = 'email_msg'
        email_node = {'id': email_id, 'type': 'Email', 'label': parsed_data['subject']}
        nodes.append(email_node)
        seen_nodes.add(email_id)

        # Domains and URLs
        for ur in url_results:
            u_id = IOCGraphMapper._stable_id("url", ur['url'])
            d_id = IOCGraphMapper._stable_id("domain", ur['domain'])

            if u_id not in seen_nodes:
                nodes.append({'id': u_id, 'type': 'URL', 'label': ur['url']})
                seen_nodes.add(u_id)
            if d_id not in seen_nodes:
                nodes.append({'id': d_id, 'type': 'Domain', 'label': ur['domain']})
                seen_nodes.add(d_id)

            edges.append({'source': email_id, 'target': u_id, 'relation': 'contains'})
            edges.append({'source': u_id, 'target': d_id, 'relation': 'resolves_to'})

        # Attachments
        for ar in attachment_results:
            a_id = f"att_{ar['hashes']['sha256'][:12]}"
            if a_id not in seen_nodes:
                nodes.append({'id': a_id, 'type': 'Attachment', 'label': ar['filename']})
                seen_nodes.add(a_id)
            edges.append({'source': email_id, 'target': a_id, 'relation': 'contains'})

        # Body IOCs (IPs and Emails)
        if body_iocs:
            for ip in body_iocs.get('ips', []):
                ip_id = IOCGraphMapper._stable_id("ip", ip)
                if ip_id not in seen_nodes:
                    nodes.append({'id': ip_id, 'type': 'IP', 'label': ip})
                    seen_nodes.add(ip_id)
                edges.append({'source': email_id, 'target': ip_id, 'relation': 'mentions'})

            for email in body_iocs.get('emails', []):
                if email.lower() == parsed_data['headers'].get('From', '').lower(): continue
                e_id = IOCGraphMapper._stable_id("email", email)
                if e_id not in seen_nodes:
                    nodes.append({'id': e_id, 'type': 'EmailAddr', 'label': email})
                    seen_nodes.add(e_id)
                edges.append({'source': email_id, 'target': e_id, 'relation': 'mentions'})

        return {
            'nodes': nodes,
            'edges': edges
        }
