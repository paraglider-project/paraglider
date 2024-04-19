.. _tagexample:

Tag Example
===========

1. Create a tag for an IP address with name `iptag`
   .. code-block:: console

        inv tag set iptag --ip 1.1.1.1

2. Assign `iptag` to a parent tag named `parenttag`
    .. code-block:: shell

        inv tag set parenttag --children iptag


3. Resolve the parent tag down to list of names
    .. code-block:: shell
    
        inv tag get parenttag --resolve

4. Create a resource name `vm1`
    .. code-block:: shell
    
        inv resource create gcp vm1 <path_to_config>

4. Add a rule referencing the parent tag to a resource
    .. code-block:: shell
    
        inv rule add gcp vm1 --ping parenttag

5. Create a tag, `iptag2`
    .. code-block:: shell
    
        inv tag set iptag2 --ip 2.2.2.2

6. Add `iptag2` to `parenttag`
    .. code-block:: shell
    
         inv tag set parenttag --children iptag2

7. Get the permit list of the resource we added to
    .. code-block:: shell
    
        inv rule get gcp vm1

8. Resolve the parent tag
    .. code-block:: shell
    
        inv tag get parenttag --resolve