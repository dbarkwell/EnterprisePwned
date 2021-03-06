﻿using System;

namespace EnterprisePwned.Data
{
    public class Fields
    {
        public DateTime AddedDate { get; set; }

        public DateTime BreachDate { get; set; }

        public string Description { get; set; }

        public string Domain { get; set; }

        public string Key => $"{Title}{Domain}";

        public DateTime ModifiedDate { get; set; }

        public string Name { get; set; }

        public string Title { get; set; }

        public string Title0 { get; set; }
    }
}