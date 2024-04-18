#include "stdio.h"
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <string.h>

static xmlNode *xml_get_element_by_path(xmlNode *root, xmlChar *path)
{
    xmlNode *cur_node = root;
    char *token;
    int children_num;
    int max_children_num;
    int i;
    xmlNode *node = NULL;

    token = strtok((char *)path, "/:");
    while (cur_node != NULL)
    {
        if (cur_node->type == XML_ELEMENT_NODE)
        {
            // printf("Current path is: %s\n", xmlGetNodePath(cur_node));
            // printf("Token is: %s\n", token);

            if (xmlStrcmp((xmlChar *)token, cur_node->name) != 0)
            {
                // printf("Mismatch with the document..!! Expected :%s, got: %s\n", token, cur_node->name);
                // printf("Current path is(%d): %s\n", __LINE__, xmlGetNodePath(cur_node));

                cur_node = xmlNextElementSibling(cur_node);
                continue;
            }
            else
            {
                // printf("Matched token: %s\n", token);

                /* If match, then find whether there is any numerics mentioned  */
                token = strtok(NULL, "/:");

                /* User specified path has completed */
                if (token == NULL)
                {
                    //printf("Travarsal completed, the value of the path: %s, is: %s\n", xmlGetNodePath(cur_node), xmlNodeGetContent(cur_node));
                    node = cur_node;
                    break;
                }
                else
                {
                    // printf("Newly found token is: %s\n", token);
                    children_num = atoi(token);

                    //printf("Here(%d)\n", __LINE__);
                    /* Check whether it is a numeric one */
                    if (children_num != 0)
                    {
                        // printf("Here(%d)\n",__LINE__);
                        // printf("Node is: %s\n",cur_node->name);
                        // printf("Parent is: %s\n", cur_node->parent->name);
                        max_children_num = xmlChildElementCount(cur_node->parent);

                        if (children_num > max_children_num)
                        {
                            printf("Not enough number of children nodes. Expected :%d, has: %d\n", children_num, max_children_num);
                            break;
                        }

                        /* Go to the i-th children. For first children no need to move to next */
                        for (i = 2; ((cur_node != NULL) && (i <= children_num)); i++)
                        {
                            cur_node = xmlNextElementSibling(cur_node);
                        }

                        token = strtok(NULL, "/:");
                        //printf("Current path is: %s\n", xmlGetNodePath(cur_node));

                        if (token == NULL)
                        {
                            node = cur_node;
                            //printf("Travarsal completed, the value of the path: %s, is: %s\n", xmlGetNodePath(cur_node), xmlNodeGetContent(cur_node));
                            break;
                        }
                    }

                    // printf("Here(%d)\n",__LINE__);
                    cur_node = cur_node->children;
                }
            }
        }
        else
        {
            cur_node = cur_node->next;
        }

        // printf("Here(%d)\n",__LINE__);
    }

    return node;
}

/* The result should be the inner product =
 * [1 2 3 ... n]*[x1 x2 x3 ... xn] =
 * 1*x1 + 2*x2 + 3*x3 + ... + n*xn */

unsigned int fn(const char *ds_file_name)
{
    unsigned int ret = 0;
    xmlDocPtr doc = NULL;
    xmlNode *root_element = NULL;
    xmlNode *node = NULL;
    xmlChar xmlPath[100];
    unsigned int computation_result = 0;
    unsigned int num_di;
    unsigned int cur_val;
    unsigned int i;

    LIBXML_TEST_VERSION

    /*parse the file and get the DOM */
    doc = xmlReadFile(ds_file_name, NULL, 0);

    if (doc == NULL)
    {
        printf("error: could not parse file %s\n", ds_file_name);
        ret = -1;
        goto exit;
    }
    strcpy((char *)xmlPath, "D/DS/");

    /*Get the root element node */
    root_element = xmlDocGetRootElement(doc);
    node = xml_get_element_by_path(root_element, xmlPath);

    if (node != NULL)
    {
        num_di = xmlChildElementCount(node);
        node = xmlFirstElementChild(node);

        for (i = 0; i < num_di; i++)
        {
            cur_val = (unsigned int)atoi((const char *)xmlNodeGetContent(node));
            //printf("Value of node: %d is: %u\n", (i+1), cur_val);

            computation_result += (cur_val * (i + 1));
            node = xmlNextElementSibling(node);
        }
    }

    ret = computation_result;
exit:
    /*free the document */
    xmlFreeDoc(doc);

    /*
     *Free the global variables that may
     *have been allocated by the parser.
     */
    xmlCleanupParser();

    return ret;
}
